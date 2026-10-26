# Open-context investigation

`open_context` measures assisted investigation with ordinary repository identity, original
ancestor history, and explicitly enabled public research. Known-vulnerability retrieval can
contribute to detection. A hit is not evidence of independent source reasoning or freedom from
pretraining exposure. Keep its detection metrics separate from closed-book and identity-reduced
observations, including observations with incomplete condition evidence.

The condition is independent of `profile`. It currently requires a `standard`, `full` input and
the externally enforced OCI `public_research` network policy. The runner refuses a local backend
or weaker policy. An incompatible adapter is unavailable, never rerun locally: Semgrep is the
current built-in OCI-compatible adapter; `llm-harness` and `deepsec` remain unsupported under OCI.
Semgrep itself does not investigate the web. Integrations that use the recorded retrieval API
must run every scanner process through the audited OCI command seam.

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

The working tree uses the normal export's regular files and executable modes. Symlinks and
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
import json, os, urllib.request

request = urllib.request.Request(
    os.environ["SCANEVAL_RETRIEVAL_URL"] + "/fetch",
    data=json.dumps({"url": "https://example.com/"}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=60) as response:
    evidence = json.load(response)
```

The scanner has no external route or external DNS. Its only reachable service is the proxy,
which allows CONNECT to declared provider endpoints and provides this retrieval API. Both paths
reject private, loopback, link-local, metadata, reserved, and translation addresses. Mixed
public/private DNS answers are denied. Connections use a validated address directly; every
redirect is independently checked, with no credentials carried across hops. Fetches are bounded
to five redirects, one MiB of response bytes, and finite connection/request timeouts.

`raw/retrieval-provenance/events.jsonl` records query, URL, source boundary, start/finish times,
outcome, redirect chain, resolved and connected addresses, content hash/length, retention status,
and model-consumption state. Successful and HTTP-error bodies are preserved by hash under
`raw/retrieval-provenance/content/` for `capture: "content", retention: "bundle"`. Choose
`capture: "hashes", retention: "hashes_only"` when content must not be retained; those responses
cannot be reconstructed from their hashes. Use retention consistent with the source's permissions.

`attempts.jsonl` is flushed before DNS or transport starts. Each completion binds to its same-id
start's effective URL, query, operation, caller-declared source, and start time. Search URLs are
derived from the declared endpoint and query before either record is written; URL userinfo is
redacted and refused. A start without a completion remains partial capture, including a request
interrupted when the scanner or proxy stops. Caller-provided source labels carry
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
