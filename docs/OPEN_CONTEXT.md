# Open-context investigation

`open_context` measures assisted investigation with ordinary repository identity, original
ancestor history, and explicitly enabled public research. Known-vulnerability retrieval can
contribute to detection. A hit is not evidence of independent source reasoning or freedom from
pretraining exposure. Keep its detection metrics separate from closed-book and identity-reduced
observations, including observations with incomplete condition evidence.

The condition is independent of `profile`. It currently requires a `standard`, `full` input and
the externally enforced OCI `public_research` network policy. The runner refuses a local backend
or weaker policy. An incompatible adapter is unavailable, never rerun locally: the built-in
OCI-compatible adapters are Semgrep and `llm-harness` on its image runtime (`config.runtime:
"oci_image"`, [below](#sv-agent-image-runtime)); `deepsec` and `llm-harness` on its host runtime
remain unsupported under OCI. Semgrep itself does not investigate the web. Integrations that use
the recorded retrieval API must run every scanner process through the audited OCI command seam.

## Complete runnable fixture

Install ScanEval and Docker, start a Docker engine, and run these from the repository root.
The two images are pinned; the backend never pulls them implicitly. On Colima, use a directory
under your shared home directory for both the configuration and workspace.

```bash
docker pull python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
docker pull semgrep/semgrep:1.177.0@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198
fixture_root="$HOME/.cache/scaneval-open-context-fixture-$(date +%s)"
python examples/open_context_fixture.py "$fixture_root"
scaneval validate run-config "$fixture_root/run-config.json"
scaneval run "$fixture_root/run-config.json" \
  --workspace-root "$fixture_root/work" --output "$fixture_root/run"
scaneval condition "$fixture_root/run/invocations/fixture__semgrep-fixture__r1"
```

This creates a fabricated source repository with an ancestor, an evaluated commit, and a later
correction, plus one pinned local Semgrep rule. Only the first two commits reach the scanner.
The target application is never started. Its draft allegation is not a reviewed benchmark label.
Semgrep produces no web retrieval API events, so this example exercises the available condition
and its evidence without demonstrating a web-using model. The real-container regression
`tests/test_v2_open_context_docker.py` additionally performs a benign public fetch and verifies
private-network denial, read-only source, hidden evaluator data, saved content, and cleanup.

The generated configuration selects this condition explicitly:

```json
{
  "snapshot_id": "fixture",
  "profile": "standard",
  "condition": {
    "name": "open_context",
    "policy": {
      "history": "ancestor_history_v1",
      "retrieval": "recorded_public_v1",
      "web_mode": "live",
      "capture": "content",
      "retention": "bundle"
    }
  }
}
```

Each system uses `execution.backend: "oci"`, a digest-pinned scanner image and proxy image,
`network_policy: "public_research"`, `execution.egress` provider host/port pairs, and
`execution.retrieval`:

```json
{
  "policy": "recorded_public_v1",
  "allowed_origins": ["https://example.com"],
  "denied_hosts": ["evaluator.example.org"],
  "capture": "content",
  "retention": "bundle"
}
```

Declare real provider hosts under `egress`; the fixture's `example.com` endpoint needs no
credential and receives no provider call. Only port 443 is allowed. Origins are exact HTTPS
origins, including every allowed redirect origin. Use `denied_hosts` for evaluator infrastructure
that has public addresses. Credentials use the existing named environment-variable injection;
values must not appear in configurations, URLs, artifacts, or command lines.

## History and source binding

ScanEval fetches complete ancestry into a fresh staging repository, then repacks exactly the
evaluated commit's reachable object closure into a different repository. It inventories every
stored object, including unreachable ones, before publishing the history artifact. Original
commit ids preserve author/committer identity, timestamps, messages, trees, and diffs. The sole
exposed head is the detached evaluated commit; refs, tags, remotes, reflogs, notes, stashes,
hooks, alternates, and fetched configuration do not cross the boundary.

The working tree uses the normal export's regular files and executable modes. Each exported
file must equal, byte for byte, what a fresh checkout of the evaluated commit writes. That
private checkout borrows the verified objects through a temporary alternate, uses a generated
configuration and a HEAD-only index, and reads every attribute, including nested
`.gitattributes`, from that index rather than from scanner-visible files. Committed built-in
`eol`, `text`, `ident`, and `working-tree-encoding` conversions therefore apply exactly as in the
normal export. No repository or operator filter command, hook, or attribute file is used; unknown
filters stay inert and Git LFS pointers stay pointers. Bytes that would only clean to the same
blob, a changed executable mode, or a blob that cannot be converted as its attributes declare all
make the input unavailable. The temporary checkout is removed on every exit. Symlinks and
gitlinks stay omitted and unfollowed; their original objects remain visible in history and are
named in `source_export_omissions`. An ancestor containing excluded `.scaneval`, `.repos`, or
harness-state paths is refused because preserving its exact objects would expose those bytes.
Shallow or incomplete ancestry, missing objects, a mismatched export, or unsafe metadata makes
the input unavailable. There is no snapshot fallback and no silent commit rewriting.

Preparation and invocation records bind the history policy, head and Git tree, reachable commit
and object counts, earliest recorded commit, root commits, exact ref inventory, sanitized Git
configuration, working-tree hash, and deterministic history digest. Installation rechecks the
artifact in each private workspace. A deterministic index tracks the exact evaluated commit;
only declared export omissions use `skip-worktree`, so Git-aware scanners see ordinary tracked
files and a clean status without following omitted links. Source and history are mounted read-only. The scanner gets
hermetic Git configuration and no host home, source cache, evaluator directory, or sibling trial.

## Recorded retrieval API

Eligible scanner integrations receive `SCANEVAL_RETRIEVAL_URL`, a service on the scanner's own
isolated network. `POST /fetch` accepts `{"url":"https://example.com/","source":"scanner_native"}`.
The optional `source` can also be `browser_tool`; this describes the integration boundary, not
independent authentication of a browser. `POST /search` accepts `{"query":"repository function"}`
when `execution.retrieval.search_endpoint` names a declared HTTPS service; the service receives
the actual URL query parameter `q`. No caller headers, cookies, URL credentials, or authorization
are forwarded. The response includes provenance plus `content_base64`.

For example, inside a scanner process:

```python
import json, os, urllib.error, urllib.request

request = urllib.request.Request(
    os.environ["SCANEVAL_RETRIEVAL_URL"] + "/fetch",
    data=json.dumps({"url": "https://example.com/"}).encode(),
    headers={"Content-Type": "application/json"},
)
try:
    response = urllib.request.urlopen(request, timeout=60)
except urllib.error.HTTPError as error:
    response = error  # Denied/failed attempts still return their structured provenance.
with response:
    evidence = json.load(response)
```

The scanner has no external route or external DNS. Its only reachable service is the proxy,
which allows CONNECT to declared provider endpoints and provides this retrieval API. Both paths
reject private, loopback, link-local, metadata, reserved, and translation addresses. Mixed
public/private DNS answers are denied. Connections use a validated address directly; every
redirect is independently checked, with no credentials carried across hops. Fetches are bounded
to five redirects and one MiB of response bytes. One 60-second monotonic deadline spans every
hop's connection, TLS handshake, status line and headers, interim `100 Continue` responses, and
body. The standard HTTP parser reads through a file that checks this deadline before and after
each buffered read, and each socket read waits at most 20 seconds or the remaining budget,
whichever is less. A server that trickles bytes cannot extend the attempt; a timeout is recorded
as a failed completion. DNS resolution remains a synchronous system call that cannot be
cancelled: a blocked resolver can exceed the budget, and an attempt interrupted then remains a
visible start without a completion.

`raw/retrieval-provenance/events.jsonl` records query, URL, source boundary, start/finish times,
outcome, redirect chain, resolved and connected addresses, content hash/length, retention status,
and model-consumption state. Successful and HTTP-error bodies are preserved by hash under
`raw/retrieval-provenance/content/` for `capture: "content", retention: "bundle"`. Choose
`capture: "hashes", retention: "hashes_only"` when content must not be retained; those responses
cannot be reconstructed from their hashes. Use retention consistent with the source's permissions.

`attempts.jsonl` is flushed before DNS or transport starts. Each completion binds to its same-id
start's effective URL, query, operation, caller-declared source, and start time. Search URLs are
derived from the declared endpoint and query before either record is written. Userinfo in the
outer URL authority, including malformed and scheme-relative forms and redirect locations, is
redacted in both journals and in the response, and the request is refused. A redirect `Location`
containing ASCII whitespace/control characters or outer userinfo, including empty or literal
`[redacted]` userinfo, is refused before it is resolved against the current URL, so an invalid
scheme such as `1https://user:secret@host/` cannot become a path request to the allowed origin.
Path and query text, including nested URLs, is recorded unchanged. A start without a completion remains partial
capture, including a request interrupted when the scanner or proxy stops. Caller-provided source labels carry
`source_assurance: "self_reported"`. Content is published atomically; retention failures return
no response bytes and remain explicit capture gaps.

## Evidence limits and reporting

`condition.json` is recomputed from saved request, result, execution, configuration, policy,
input provenance, history audit, retrieval events, and retained-content bytes. It distinguishes
declarations, external enforcement, observed capture, and unavailable or unverifiable portions.
Changing any bound artifact invalidates the record. Missing capture remains `capture_gap`;
zero events never proves that no research occurred.

Provider CONNECT tunnels remain encrypted. Their allow/deny decisions and byte counts are
observed, while provider-side searches, browser/native retrieval inside a tunnel, URLs,
redirects, and response bodies remain unverifiable. Direct socket attempts blocked by the
isolated network are unobserved and are recorded separately from observed proxy denials.
No provider attestation is implemented in this backend. Fetched content's
`content_entered_model` stays `null`: receipt is not evidence of inclusion in a model request.
An integration needs an independently observed request binding to make that narrower claim.

All runs currently use live retrieval. Preserved responses support offline inspection; they do
not make live Internet content or opaque provider activity deterministically replayable. Treat
repository instructions and retrieved pages as untrusted data. They have no evaluator tool,
destination, scoring, or label authority. A declared allowed endpoint still receives whatever
the scanner sends it; the model provider, retrieval services, pinned images, and Docker engine
are trusted parts of this boundary ([threat model](THREAT_MODEL.md)).

Condition coverage and capture/history coverage belong beside detection metrics. Aggregation
must keep `open_context` separate from `closed_book_standard`, `identity_reduced`, and failed or
incomplete attestations; never publish one pooled headline detection rate across those groups.

## SV-Agent image runtime

`llm-harness` has two runtimes. `local` (the default, unchanged) runs a host checkout of the
harness and is refused under `oci`. `oci_image` runs an image-owned runtime and is accepted only
under the `oci` backend with `public_research`: it is refused before preparation, and again when
the scan starts, on any other backend or policy, so closed-book systems never receive its research
tools. Preparation inspects nothing on the host; the configured paths are inside the image.

The image holds Node, the pinned upstream harness under `/opt/scaneval/harness` with its own
`tsx`, Pi, the observer SDK, and copies of `llm_harness_driver.mts`, `pi_oci_runner.mts`,
`pi_open_context.mts`, `pi_open_context_tools.mjs`, and the diagnostic
`pi_synthetic_provider.mts` from `src/scaneval/adapters/`, plus a receipt at
`/opt/scaneval/runtime.json` (`harness.commit`, `harness.package_version`, `pi.version`,
`node.version`, or the same names flattened with underscores). The driver runs with the image's
`tsx` from the mounted workspace and reports the receipt, the Pi and Node versions the processes
themselves report, and digests of the driver, runner and extension files it loaded. Real model
runs require runtime identity, a readable receipt and Pi route metadata. The host compares its
driver, OCI runner, extension and tools-helper hashes with both `runtime.files` and
`receipt.adapters`; absent or different hashes produce `runtime_mismatch`. The driver hash is
recorded in tool versions. Required `expected_harness_commit` and `expected_pi_version` default
to the Dockerfile pins `f959cbcf010c7e41f780c718b65b1724d3aecb43` and `1.4.0`; explicit overrides
must also match. Synthetic diagnostics do not attest host/image adapter identity.

```json
{"system_id": "sv-agent-open-context", "adapter": "llm-harness",
 "config": {"harness": "securevibes-agent", "runtime": "oci_image", "model": "openai-codex/gpt-5.6-sol",
            "thinking_level": "high", "expected_harness_commit": "f959cbcf010c7e41f780c718b65b1724d3aecb43",
            "expected_pi_version": "1.4.0"},
 "execution": {"backend": "oci", "image": "<sv-agent image>@sha256:<digest>",
               "proxy_image": "<proxy image>@sha256:<digest>",
               "egress": [{"host": "chatgpt.com", "port": 443}],
               "credentials": [{"env": "SV_AGENT_PI_AUTH_JSON", "provider": "openai-codex"}],
               "retrieval": {"policy": "recorded_public_v1", "allowed_origins": ["https://nvd.nist.gov"],
                             "capture": "content", "retention": "bundle"}}}
```

The route. `openai-codex/<model>` is the only provider route; any other provider or model is
refused, and a harness stage asking for another route fails rather than being redirected.
`thinking_level` (default `high`) is applied to every call, whatever the stage asked for, and the
override is counted. The image runner replaces only the innermost exec of the harness: it is
composed under the harness's own `createRetryingPiRunner(createIsolatedPiRunner(...))`, so retry
classification, per-call temporary working directories and argv NUL escaping stay upstream's, and
no stage, prompt or file selection changes. Its transport differences are stated in
`pi_oci_runner.mts`: the prompt travels on stdin (Pi trims leading and trailing whitespace of
piped input), Pi runs in JSON mode and the engine receives exactly the text `--print` would have
printed, and argv is rebuilt with `--no-extensions -e <extension>`, an exact `--tools` allowlist,
and MCP, skills, prompt templates, themes, context files and project trust disabled. Pi's own
`--no-tools` would remove the extension's tools too; stage-passed `--no-tools` is replaced by the
allowlist and counted.

The tools. `scaneval_fetch` and, only when `execution.retrieval.search_endpoint` is declared and
`config.research_search` is `true`, `scaneval_search` post to `$SCANEVAL_RETRIEVAL_URL` directly,
never through the inference proxy, labelled `browser_tool`. `scaneval_git` runs fixed read-only
history operations (`log`, `show`, `file`, `blame`, `grep`) against the repository root the driver
names, not the per-call temporary directory, with no user or system Git configuration.
`scaneval_read` reads or lists the exported source and cannot leave it. No built-in Pi tool is
declared: the built-in file tools read any absolute path, which includes Pi's agent directory and
the run's raw output. `config.research_preflight_url` makes the driver fetch one URL before any
model call, labelled `scanner_native` and reported as transport evidence, not research.

Three separate statements. The extension journals, per Pi process, which tools it registered
(availability) and the metadata of each call it served; Pi's JSON stream reports each tool
execution (execution); and nothing establishes that a result entered a model request or shaped a
finding (consumption), which stays unverifiable. If Pi ran without any journaled registration,
or a recorded registration lacks required tools, the run is `partial`
(`research_tools_unavailable`). Registration counts are reported alongside Pi call counts;
the adapter does not establish a one-to-one correspondence. Pi's message metadata names the
provider and model Pi addressed; that is the client's routing record, so no resolved model is
recorded, and a route other than the pinned one is an error.

The credential. Refresh the operator's credential once before launching shards, then export
an **access-only** JSON object with one `openai-codex` key in the variable named by
`config.pi_auth_env` (default `SV_AGENT_PI_AUTH_JSON`). Its OAuth entry accepts only `type`,
`access`, `expires` (Unix milliseconds), and optional `accountId`; omit `refresh` and every
other field. Declare that variable under `execution.credentials` with provider `openai-codex`.
The `GIT_`, `SCANEVAL_` and `PI_` variable namespaces are refused. The adapter rejects refresh
material and unknown fields before starting any container and never rewrites the host environment.
An API key, second provider, malformed or non-finite expiry, or insufficient token lifetime is
refused without printing credential values or field names supplied by the credential.

The access token must outlive the configured scan timeout plus Pi 1.4.0's five-minute refresh
window and a sixty-second margin. The driver checks the access-only document again, removes its
variable before the harness loads, and writes only the permitted fields plus a nonsecret disabled
refresh sentinel to `auth.json` (mode 0600) in the container's private `/tmp` agent directory.
Pi receives an allowlisted environment without the credential variable, and the directory is
removed when the scan ends. The sentinel satisfies Pi's OAuth record shape; sufficiently fresh
access credentials use its normal OAuth resolver without refreshing. No real refresh token is
forwarded or written inside a scan, and there is no fallback to a paid provider.

The pinned harness's native `summary.completion` report is required for the image route. Invalid
execution evidence, unknown states, inconsistent logical-call counts, failed or pending calls,
and incomplete or unknown coverage produce `partial`, preserving native reasons and any findings
already imported. A legacy local harness may omit the report; an explicitly malformed report is
not treated as legacy absence. Research/history attestation and scan assessment completeness
remain separate: the synthetic image fixture can attest `open_context` while its native source
assessment is `unknown`, so its outcome is `partial`.

ScanEval also understands the corrected additive `summary.reviewWorkflow` version 1 contract from
newer SV-Agent builds. A reconciled positive report is labelled only as a **completed declared
bootstrap review workflow**. The consumer recomputes the portable public inventory digest and
reconciles original classification/policy, observed native inputs, dispatched-call
invocation/request/response identity, obligations, terminals, and planner/anchor/structural/lint
stage evidence. Repository metadata recognition is limited to extensionless README/LICENSE/
COPYING/NOTICE and `.md`, `.rst`, `.adoc`, or `.txt`; unknown and executable suffixes remain
unsupported and cannot forge the metadata-exclusion reason. Source assessment remains
`unassessed`; this is native producer-declared and cross-checked byte identity, not provider
attestation, semantic proof, or a claim that source is safe. Exact legacy execution-anchor gaps may
be explained only by inventory-backed explicit exclusions; failed anchors and unsupported source
remain blocking. Malformed, incomplete, unknown, unsupported-mode, stale, cross-bound, omitted,
duplicate, inconclusive, failed-stage, or failed/pending-call evidence stays `partial`, with
imported findings retained. Legacy behavior is unchanged when the field is absent, and a malformed
present field cannot fall back to legacy success. The final preview contract was reconciled at
upstream head `73ae7aa9ba14425abb066306cfabfea4fd83d3eb`; upstream PR 206 remains pending Anshuman
review and must not be auto-merged. The default image pin below still predates it.

The image default remains the upstream revision
`f959cbcf010c7e41f780c718b65b1724d3aecb43`, which predates `reviewWorkflow`. Its
source-assessment contract has no completed state: delivered source remains `unassessed`, and
missing source evidence remains `not-recorded`. Both add an unknown-coverage reason, so a
successful model response at the default pin still cannot produce a completed source-scan score
through this route. Findings and diagnostic evidence remain available. Before the coordinated
image pin changes, a bounded smoke may opt in only by building the image from the exact reviewed
upstream commit and naming that same full commit with the existing `expected_harness_commit`
override. The public default must not imply that the preview contract has merged. Do not treat
consumer support alone as live acceptance or as readiness for broad-corpus scoring.

`model: "scaneval-synthetic/deterministic-open-context"` selects a DIAGNOSTIC in-process provider
that calls no model: it issues `synthetic_tool_calls` and then answers with the harness's own
deterministic mock response. It exists to exercise the route inside the real boundary
(`tests/test_v2_sv_open_context_docker.py`, gated on `SCANEVAL_SV_IMAGE`); its results are recorded
as diagnostic and are never scanner evidence. Live support for the real route is not verified until
the pinned image has run the bounded live smoke described in
[the design](designs/sv-agent-open-context.md).
