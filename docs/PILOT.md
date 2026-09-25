# First real-case pilot, 2026-09-20

This is the first end-to-end slice on real repositories: prepared inputs, six real
scanner invocations across two systems, preserved native output, machine-drafted review
records, and offline replay. It is a pipeline demonstration, not a benchmark result. No case has been
independently reviewed, no matching decision has been approved, and every number below is
therefore either an execution fact or a zero by construction.

The run records are not committed. Every number below was read from the records this
build produced, and the frozen run configurations in `corpus/pilot/` reproduce them. See
"Reproducing the runs" below.

Two things happened after this pilot and are recorded here rather than folded into it: the
harness gained observation surfaces the driver now uses where it finds them, described
under "What a hooked harness build changes", and two further runs on one input on
2026-09-25 — a third system, and the harness itself through the hooked driver — described
under "Later pipeline exercises".

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

What those statuses mean, stated as limits **of this run**. The harness build it ran
against, `c918011`, exported no observation surface of its own, so the driver saw only
what it could wrap from outside. A later build changed three of the four; what it changed
and what it did not is the next subsection.

- **Model events are partial, not complete.** The observer wrapped the harness's own model
  runner, and that runner retries internally, below the observed boundary. One event is
  one logical call, not one attempt, and the text-mode CLI path exposed no token usage.
- **Tool dispatch is unavailable, and that is not the same as absent.** The claude route
  denies only network and spawn tools; file tools such as Read and Bash remain permitted
  inside the CLI's isolated working directory. Those calls happen inside a subprocess this
  driver spawns but cannot see into. No tool event was emitted, and that establishes
  nothing about whether a tool ran. Each route's declared tool policy is recorded as the
  harness's own declaration, never as an observation.
- **The finding lifecycle is only observed at submission.** Candidate creation,
  validation attempts and filtering happened inside the harness and were not exposed at
  the boundaries this driver instrumented. A question like "where did the harness drop
  this finding" cannot be answered from these records.
- **Context selection is partial.** Only the harness's own progress notes are recorded as
  context events. The complete outgoing prompt is captured separately as model-request
  content, which is the stronger evidence of what actually reached the model.

Model identity is recorded as `unverified` for this run: the requested route is known,
`anthropic/claude-sonnet-5`, but neither CLI reported the model that served the call at
that build. Cost is recorded as unknown. The harness's own estimate for this run, 3.2 USD,
is a file-count heuristic and is preserved as its self-report, not as a measurement.

### What a hooked harness build changes

The harness gained two optional observation surfaces after this run, and the ScanEval
driver (version 2.2.0) feature-detects each one rather than assuming it: the runner hooks
(`PI_RUNNER_HOOKS_VERSION`) and the engine observer (`HARNESS_OBSERVER_VERSION`). A
checkout exporting neither is observed exactly as this run was, which is what keeps an
older checkout working. Nothing above became wrong; it became specific to the build it
describes.

Against a build that exports them:

- **Retries are observable.** One model request/response pair per CLI attempt, from inside
  the harness's own retry loop, each carrying the attempt number, the maximum, the retry
  decision and its backoff, joined to its call by `call_id` with an `attempt_id` of
  `<call_id>/attempt-<n>`.
- **Token usage and a cost estimate exist on the claude route.** The driver asks for
  `--output-format json`, so each attempt also carries the CLI's own token counts, its
  cost estimate, the turn count, the session id and the served model id, while the engine
  still receives exactly the text a text-mode run would have printed. The category stays
  `partial` regardless: an attempt is a CLI invocation rather than an API request, so the
  turns inside one attempt are not visible from here, and the pi route reports no usage at
  all. A CLI-reported cost is an estimate, never a bill.
- **Context selection becomes the engine's own report.** One event per instrumented
  invocation carrying every span the engine placed in that prompt: path, line range,
  character count, the sha256 of exactly the text supplied, the role it played, and
  whether the text could be located in the file. The category stays `partial` for the run,
  because the threat planner's model calls and some specialist invocations are not
  instrumented, so a model request with no context event beside it is an uninstrumented
  call, not a call that was given no context.
- **Candidate creation and filtering become observable,** under the engine's own candidate
  ids. Validation becomes `not_applicable` rather than `unavailable`: the validation stage
  is the consensus judge, the judge runs in pr mode, and this adapter refuses every mode
  but bootstrap. That is "this run had no such stage", which is a different statement from
  "there was one and it could not be seen".
- **Tool dispatch does not change.** It still happens inside the model CLI subprocess, and
  the claude route runs with `--no-session-persistence`, so no session transcript is left
  behind for `scaneval.collectors` to read either. It stays unobserved on that route.

The full per-category matrix, per harness build, is in
[the observer SDK guide](OBSERVER_SDK.md). That document is the only copy of it and a test
parses it, so it is not repeated here.

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

# Own harness, one input, live model calls. This configuration is the Haiku one that
# produced the 2026-09-25 run below, not the Sonnet configuration of 2026-09-20.
scaneval run corpus/pilot/run-harness.json --output <new dir> --only-input fastify-v5.12.1

# Third-party scanner, one input, live model calls.
scaneval run corpus/pilot/run-deepsec.json --output <new dir> --only-input fastify-v5.12.1
```

Output directories must not exist. The harness run makes real model calls through the
local `claude` CLI login and took about nine minutes for one input at its current Haiku
settings; the 2026-09-20 figures above came from a Sonnet configuration this file no
longer carries, so that run reproduces as a run of the same shape, not as the same
numbers.

The DeepSec run makes real model calls too, and took about four and a half minutes for one
input at `limit: 6`. It also needs an installed DeepSec workspace, and `run-deepsec.json`
points at one under `~/Documents/GitHub/sec-test-repos/.deepsec`, which is a path you must
change to your own.

## Later pipeline exercises, 2026-09-25

Two runs on the Fastify input, on the cheap model route, neither of them a detection
result: a third system for the first time, and the own harness again against a build that
exports the hooks.

### DeepSec on Fastify

A third system now has an adapter. DeepSec (`vercel-labs/deepsec`, pinned at 2.3.10) is a
third-party scanner ScanEval runs unchanged through its own CLI: `scan` for regex
candidates, `process` for the agent investigation, `export` for the findings. Nothing in
it is patched or wrapped, and the adapter reads its records afterwards rather than
observing it as it works. The frozen configuration is
[`corpus/pilot/run-deepsec.json`](../corpus/pilot/run-deepsec.json) and the adapter,
including its own capture matrix, is documented in [the DeepSec adapter](DEEPSEC.md).

It was run twice on 2026-09-25 against the Fastify snapshot with `claude-haiku-4-5`,
`thinking_level: low`, `limit: 6`, `batch_size: 3`, `concurrency: 1`, trace mode
`content`. Both completed with status `success`.

| Observation | First run | Second run |
|---|---|---|
| Trace events, capture gap, dropped events | 148, none, 0 | 118, none, 0 |
| Agent sessions, transcripts imported | 2 of 2 | 2 of 2 |
| File records written by `scan` | 35 | 35 |
| Files `process` investigated | 6 | 6 |
| File records left `pending` by the limit | 29 | 29 |
| Regex candidates read from those records | 40 | 40 |
| Claims | 5 | 2 |
| Routed candidates | 0 | 0 |
| DeepSec's own cost estimate | 0.2956 USD | 0.2618 USD |
| Wall | 254.2 s | 267.8 s |

**This is a pipeline exercise on the cheapest route with a file limit. It is not a
detection result and not a measurement of DeepSec.** `limit: 6` means `process`
investigated six of the 35 files `scan` had recorded and left the other 29 `pending`. The
six it picked were all GitHub Actions workflow files; `lib/four-oh-four.js`, the file the
Fastify case names, was never among them. Nothing routed, and at this limit nothing could
have. Raising the limit is a cost decision, not a fix for these numbers.

The two runs disagreeing on claim count, five against two, is the ordinary nondeterminism
of an LLM-backed scanner at one configuration. Both are recorded; neither is averaged away
and neither is the run.

The cost and token numbers are DeepSec's own per-file shares of each batch, summed back
into batch totals. They are CLI-reported estimates, never a bill, and no single number
among them measures one model call.

One defect this pair exposed and fixed. In the first run every context span was recorded
as `external:<basename>` rather than workspace-relative: on macOS the scanned temporary
directory is spelled `/var/folders/...` while the paths in the imported transcripts are
its realpath under `/private/var/...`, so no span matched the workspace root and the
adapter honestly recorded each one as outside the workspace. The collector now takes every
spelling of the root, and the second run recorded all of its spans workspace-relative. The
first run's trace still says what was observed then and was not rewritten.

A second defect the pair exposed and fixed. DeepSec needs the installed `node_modules`,
so the private workspace holds a symbolic link to it, and staging cuts that link and
records where it pointed. In the first run that target was written out as the operator's
absolute home path; it is now spelled with a leading `~`, which is what the second run
recorded. The directory structure below the home is kept, because that is what says where
the link went; only the prefix naming the machine and the account is replaced.

### The own harness through the hooked driver, on Fastify

The harness was then run again on the same input, this time against a build that exports
both hooks, to see what the driver records when it finds them. Harness `c918011` with the
hook changes in its working tree, which the driver records as a dirty checkout; driver
version 2.2.0; model route `anthropic/claude-haiku-4-5`; `llm_max_files: 25`;
`bootstrap` mode; trace mode `content`. Status `success`, and `degraded` with the `lite`
runtime profile because `qmd` is absent on this machine, exactly as the 2026-09-20 run
was.

| Observation | Value |
|---|---|
| Hooks detected | runner 1, engine 1 |
| Model invocations, CLI attempts, failed attempts | 13, 13, 0 |
| Invocations the engine reported context for | 12 of 13 |
| Context spans, spans outside the workspace | 197, 0 |
| Distinct files supplied across those spans | 38 |
| Trace events, capture gap, dropped events | 48, none, 0 |
| Candidates, filtered, validations, submitted | 5, 0, 0, 5 |
| Claims | 5 |
| Routed candidates | 0 |
| Served model, as the CLI reported it | `claude-haiku-4-5` |
| CLI-reported cost estimate | 1.2358 USD |
| Tokens: input, output, cache read, cache creation | 121, 49,057, 188,886, 485,765 |
| Wall | 551 s |

The 48 events are 13 model requests, 13 responses, 12 context selections, 5 candidates and
5 submissions. Every one of them carries `capture_status: complete`, while the run-level
context category is `partial`, and both are right: one invocation of the thirteen reported
no context, and the run-level status is about the run rather than about any event in it.
The candidates and submissions are the engine's own records, linked through the engine's
own ids rather than read off the returned summary.

Three things are recorded here that the 2026-09-20 run could only declare unobservable,
because that run was against a build exporting neither hook:

- **Attempts.** Thirteen CLI attempts behind thirteen invocations, none retried, none
  failed; every request records `retries_observable: true`, `output_format: json` and a
  maximum of five attempts. The count is dull precisely because nothing went wrong. What
  it establishes is that a retry would now be an observation rather than an event folded
  into its neighbour.
- **Usage, cost and the served model.** Read from the claude CLI's own json result,
  including the two cache counts the scan result's `usage` field does not carry and the
  served model id the earlier run had to record as unverified. It is still the CLI
  reporting on itself: `verification` stays `self_reported`, and the cost is an estimate,
  never a bill. The token totals are floors, because an attempt that reported nothing
  contributes nothing to them.
- **The code the engine actually placed in each prompt.** 197 spans over 38 files, none
  truncated, none reassembled out of fragments, and none outside the workspace. No home
  path appears anywhere in the trace.

One number is worth reading twice. The harness's own self-report says `llm_calls=12`; the
runner hooks counted 13. The extra one is the invocation the engine reported no context
for, recorded as `call-1` with no stage at all, and it ran before the twelve tagged
hypothesis calls — which is where the threat planner runs, and the driver's own note says
the planner reports no context. The record does not name it, so read the gap as what it
is: one model call a self-report did not count, which a self-report is not in a position
to notice about itself.

Tool dispatch stayed unobserved, as it does on this route whatever the harness exports.

Nothing routed. The five claims sit on `lib/config-validator.js`, `lib/reply.js`,
`lib/validation.js`, `lib/error-handler.js` and a test script. None is on
`lib/four-oh-four.js`, the file the Fastify case names, so no claim became a candidate for
human review — where the Sonnet run of 2026-09-20 produced one. Two runs at different
model routes and different file budgets; that difference is not a comparison.

#### What the coverage diagnostic says about this run, and what it does not

`scaneval diagnose context-coverage` on this bundle classifies the case's one target
**`unknown`**, and records why: `target_locations_without_line_range`, because the pilot
label for `lib/four-oh-four.js` declares a path and a note saying the exact accepted range
is not yet reviewed, so there is no range for a span to cover; and
`context_capture_partial_at_run_level`, because one invocation of the thirteen reported no
context, which blocks any claim of absence for the whole run.

Separately, and as a fact about the record rather than a classification: that file is not
among the 38 the engine reported supplying. That is what the trace says and all it says.
It is not a finding that the file was never read — a model's own tool call is not a
context span, and tool dispatch is unobserved on this route — and with run-level capture
partial it establishes no absence. The diagnostic's answer is `unknown`, and `unknown` is
the answer. Giving the label a reviewed line range, and instrumenting the planner call,
are the two things that would let the question be answered either way.

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
- **Nothing at all about DeepSec's detection ability.** Its two runs investigated six
  files chosen by its own ordering under a cost limit, none of them the file the case
  names. That measures the pipeline, not the scanner.
- **Nothing about the harness on Haiku either, and no comparison with its Sonnet run.**
  One run, one model route, one file budget, no repetition. The 2026-09-25 harness figures
  demonstrate what the hooks record, not how well anything scans.

## Next

1. Human review of the 13 routed candidates, recorded through `scaneval review record`
   and `scaneval review approve`, which is the only path to a non-zero recall.
2. Independent review of the three case labels to L3, which is the only path out of draft
   scope.
3. Fixed-state snapshots to give the cases property-specific negative controls.
4. The harness on the remaining two inputs, and repetitions, before any comparison.
5. The remaining two inputs against a hooked harness build. Fastify has been run that way;
   oauth2-proxy and FastMCP have not, so retries, token usage, supplied-context spans and
   the candidate lifecycle are still unrecorded for them.
6. A reviewed line range on the Fastify target, and the planner invocation instrumented,
   which are the two things that would move that target's coverage classification off
   `unknown`.
