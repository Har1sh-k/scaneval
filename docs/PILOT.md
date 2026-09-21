# First real-case pilot, 2026-09-20

This is the first end-to-end slice on real repositories: prepared inputs, two real
scanner invocations, preserved native output, machine-drafted review records, and offline
replay. It is a pipeline demonstration, not a benchmark result. No case has been
independently reviewed, no matching decision has been approved, and every number below is
therefore either an execution fact or a zero by construction.

The preserved records are under [`corpus/pilot/runs/`](../corpus/pilot/runs). Exported
source trees are excluded; everything else each run produced is there.

## What was evaluated

Three pinned snapshots, one draft case each. Every commit was verified against the
repository with a shallow fetch on 2026-09-20; the pack records how each was chosen.

| Case | Snapshot | Language | Workload | Mechanism |
|---|---|---|---|---|
| `oauth2-proxy-cve-2025-54576` | oauth2-proxy `f4b33b64`, parent of fix `9ffafad4` | Go | conventional application | Skip-auth regex matched the full request URI including the query, so query text could satisfy a public allowlist entry for a protected path. |
| `fastmcp-cve-2026-32871` | FastMCP `c861862a`, parent of fix `40bdfb6b` | Python | agentic application | MCP-client-supplied path parameters were substituted into a backend URL without encoding, escaping the intended prefix while authorization headers stayed attached. |
| `fastify-cve-2026-76169` | Fastify tag `v5.12.1` (`7d196a99`) | JavaScript | conventional application | A malformed request target reaches a custom not-found handler and skips that handler's `preHandler` hook chain. |

The Fastify snapshot is the release tag rather than the fix parent: the fix landed on
`main`, which carries version `6.0.0-alpha.2`, so the parent commit does not represent the
affected release line. Its backport into `v5.12.2` is not yet verified.

Coverage is deliberately narrow. There is no Rust case, no conventional-automation case,
and no AI-assisted-application case. One case per repository, one repository per
mechanism.

## Systems

| System | What it is | Pin |
|---|---|---|
| `semgrep-oss-1.177.0-rules-40b8c63f` | Semgrep OSS, a conventional rule engine | Binary 1.177.0; rules are a git checkout of `semgrep/semgrep-rules` at `40b8c63f`, 618 rule files across the python, javascript, typescript and go trees. No registry download, metrics off. |
| `securevibes-agent-claude-sonnet-5-bootstrap` | The own harness, an LLM-backed scanner, run in its `bootstrap` mode through its own engine entry point | Harness at `c918011`, package `0.1.0`; model route `anthropic/claude-sonnet-5`, served by the `claude` CLI; at most 40 files sent to the model. |

Both systems ran on all three inputs.

The Semgrep records in this repository were produced by this build. The harness records
were produced before the project was renamed, and run bundles bind to each other by
content hash, so they were not relabeled. They are kept locally under `results/` rather
than committed; their figures are reported below and their bundles are available on the
machine that produced them. Later harness runs use a cheaper model route, so repeating
them will not reproduce these numbers exactly.

## Execution results

Every invocation completed. These are execution facts, not detection results.

| Run | Input | Status | Claims | Wall | Routed candidates |
|---|---|---|---|---|---|
| Semgrep | oauth2-proxy | success | 49 | 16.9 s | 6 |
| Semgrep | FastMCP | success | 166 | 25.8 s | 0 |
| Semgrep | Fastify | success | 66 | 18.0 s | 6 |
| Harness | oauth2-proxy | success | 6 | 950 s | 0 |
| Harness | FastMCP | success | 4 | 1070 s | 0 |
| Harness | Fastify | success | 3 | 729.5 s | 1 |

The two systems differ by about twenty times in volume and a thousand times in wall time.
Semgrep produced 281 claims across the three inputs in 61 seconds and made no model call.
The harness produced 13 claims in 46 minutes across 66 model calls, and captured 145 trace
events with no capture gap in any run.

A routed candidate means only that a claim's primary location path is an accepted
location path of the target. Routing is a queue for human review. It is not a match, and
path equality is not an allegation.

Confirmed detections across every run: **zero**. Recall is 0.0 on each input with the
candidates pending, because no human has reviewed any of them. That is the intended state
of a draft pack, not a measurement of either system.

### What the two systems actually alleged near the targets

On Fastify, the same file under the same accepted location produced very different text.

Semgrep's six routed candidates on `lib/four-oh-four.js` were five instances of `const`
being assigned twice and one prototype-pollution note. None concerns request-target
handling or the hook chain.

The harness's single routed candidate on the same file reads:

> 404 bad-URL/oversized-param dispatch bypasses the onRequest/preValidation/preHandler hook chain

That describes the mechanism the case records. It is recorded as `unresolved` and earns
nothing. Whether it meets the matching rules, in particular whether it identifies the
affected input and the encapsulation boundary the case requires, is a human decision that
has not been made. Read this as the contrast the benchmark exists to put in front of a
reviewer, not as a detection.

On oauth2-proxy, Semgrep's six routed candidates were five shared-URL-struct mutation
warnings and one open-redirect warning, none about path-versus-URI matching. The harness
produced six claims on that input and none routed: they concern provider group validation,
forwarded-header parsing, CSRF cookie handling, header injection and cookie entropy, not
the skip-auth matching surface the case names.

On FastMCP nothing routed from either system. Semgrep produced 166 claims, none in the
file the case names. The harness produced four, one of which describes the case's
mechanism but at a different file than the accepted location, so it did not route. That
claim has been referred to private human review under the disclosure boundary in the
design, and is deliberately not described here, in the corpus, or in any trace. Nothing
about it is a benchmark result, and no part of it may be published before that review
reaches a decision.

Claim kinds show the mapping honestly. All 49 oauth2-proxy claims and all 66 Fastify
claims mapped to `unmapped` because their rules carry no CWE in the six benchmark
families. Unmapped claims are kept, never dropped.

## Capture

Per-category capture status, taken from the execution records rather than asserted here.

| Category | Semgrep | Harness |
|---|---|---|
| Model requests and responses | not applicable | partial |
| Tool calls | not applicable | **unavailable** |
| Context selection | not applicable | partial |
| Finding submitted | not applicable | complete |
| Finding candidate, validation, filtering | not applicable | unavailable |

The harness run captured 41 events with no capture gap and no dropped events: 19 model
requests, 19 responses, and 3 submissions. Content mode stored the complete outgoing
prompt for every call, which is the model-visible context after the harness selected it.

What those statuses mean, stated as limits:

- **Model events are partial, not complete.** The observer wraps the harness's own model
  runner, and that runner retries internally, below the observed boundary. One event is
  one logical call, not one attempt. Token usage is not exposed by the CLI path at all.
- **Tool dispatch is unavailable, and that is not the same as absent.** The claude route
  denies only network and spawn tools; file tools such as Read and Bash remain permitted
  inside the CLI's isolated working directory. Those calls happen inside a subprocess this
  driver spawns but cannot see into. No tool event was emitted, and that establishes
  nothing about whether a tool ran. Each route's declared tool policy is recorded as the
  harness's own declaration, never as an observation.
- **The finding lifecycle is only observed at submission.** Candidate creation,
  validation attempts and filtering happen inside the harness and are not exposed at the
  boundaries this driver instruments. A question like "where did the harness drop this
  finding" cannot be answered from these records yet.
- **Context selection is partial.** Only the harness's own progress notes are recorded as
  context events. The complete outgoing prompt is captured separately as model-request
  content, which is the stronger evidence of what actually reached the model.

Model identity is recorded as `unverified`: the requested route is known,
`anthropic/claude-sonnet-5`, but neither CLI reports the model that served the call. Cost
is recorded as unknown. The harness's own estimate for this run, 3.2 USD, is a file-count
heuristic and is preserved as its self-report, not as a measurement.

The run was marked `degraded` with a `lite` runtime profile because `qmd` is absent on
this machine. One of 18 harness model calls failed, leaving hypothesis coverage at 0.889.
The harness's own scan status was `ok`, so the invocation is recorded as `success`, with
all of these figures preserved in the execution record.

## Isolation and provenance

Each invocation ran against a fresh export in a private workspace outside the run
directory. Verified for both runs:

- The exported tree hash matched the hash recorded in the pack.
- The source was unmodified after the scan: `source_modified` is false.
- The harness received a single synthetic commit with a neutral identity, because it
  requires git. Original history is never exported.
- The harness's `.securevibes` state directory was captured into the bundle as scanner
  output, and its plan, threat model, scan log, profile and specialist records are
  preserved.
- No evaluator artifact was reachable from the workspace. A grep for target ids, accepted
  locations and pack hashes across the captured harness state returns nothing.

The declared network policy is recorded, not enforced: `none` for Semgrep,
`model_provider_only` for the harness. Enforcement belongs to the execution environment.
Directory separation documents the evaluator boundary; it is not a sandbox.

One defect this run exposed: four harness plan artifacts were declared at paths inside the
workspace, which is removed once the scan returns, so they dangled and were not hashed.
Their content survived through the state-directory capture. The fix, copying those records
into the staging directory before the workspace is removed, landed after this run, so the
preserved records still carry the four "declared artifact missing" notes.

## Replay

Replaying a bundle offline reproduces its evaluation byte for byte, and prints a warning
because the decisions carry no recorded human approval:

```sh
scaneval replay <your run directory>/invocations/<invocation id>
# scaneval: review state draft: these numbers come from decisions with no recorded human approval
```

Replay reads the saved result and the frozen evaluator records. It makes no model or
network call, and it does not re-execute the scanner.

## Reproducing the runs

```sh
# Re-check the pack against each pinned snapshot (fetches the pinned commits).
scaneval corpus validate corpus/pilot/pack.json --snapshot-id oauth2-proxy-f4b33b64 --cache-root .repos --trial-root <new dir>

# Pinned conventional scanner, all three inputs.
scaneval run corpus/pilot/run-semgrep.json --output <new dir>

# Own harness, one input, live model calls.
scaneval run corpus/pilot/run-harness.json --output <new dir> --only-input fastify-v5.12.1
```

Output directories must not exist. The harness run makes real model calls through the
local `claude` CLI login and took about 12 minutes for one input.

## What this pilot does not establish

- **No detection performance for either system.** Every candidate is unresolved. A recall
  number requires human review of both the case labels and the matches.
- **No comparison between the two systems.** They ran on overlapping but unequal inputs,
  one of them once, with no repetitions and no uncertainty estimate.
- **No claim about contamination or memorization.** Two of the three disclosures predate
  the evaluated model's documented cutoff. Prior knowledge would earn credit anyway under
  the design, and nothing here measures it.
- **No negative-control evidence.** The pack defines no controls yet, so the control rates
  are N/A rather than zero, and no fixed snapshot has been prepared.
- **No claim that the harness cannot do better, or that Semgrep cannot.** One harness
  configuration, one mode, one model, one run.

## Next

1. Human review of the four routed candidates, recorded through `scaneval review record`
   and `scaneval review approve`, which is the only path to a non-zero recall.
2. Independent review of the three case labels to L3, which is the only path out of draft
   scope.
3. Fixed-state snapshots to give the cases property-specific negative controls.
4. The harness on the remaining two inputs, and repetitions, before any comparison.
