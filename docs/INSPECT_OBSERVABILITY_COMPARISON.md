# Inspect AI and ScanEval: visibility and observability

Reviewed 2026-10-17. Inspect AI's Python SDK source is cloned at
`.repos/inspect_ai__a6993763` from the ScanEval repository root (ignored by Git),
pinned to commit `a699376315c95b6410f5aec01af37c8dec452aea` from 2026-10-16.
Its viewer submodule, `src/inspect_ai/_view/ts-mono`, is also checked out at
`b07f814c50bc3fdeb141d2ba5b31a37d43a12b9d`.
ScanEval was reviewed at `f4831c3a3d31bc5ad446560a05dd9dbf846724b3`.
This compares implementation and documentation, with executable ScanEval
reproductions. It is not a performance benchmark or a live-provider comparison.

## Recommendation

All evaluation runs are private. The intended downstream workflow sends their
saved evidence to an LLM for RSI; this is an owner-specified project requirement.
Preserve source excerpts, prompts, tool arguments/results, failures, and supplied
evaluation decisions in content traces so that later analysis can use them.

Start with capture correctness and the saved-trace path. Repair data loss,
validate what each bundle actually contains, then provide a machine-readable
evidence export and human investigation view. Include effective run configuration,
artifact identities, decision reasons, and capture gaps in the LLM input.
The comparison and proposed export do not themselves send any run to a model.

Retaining evaluation content is expected in this private workflow. Keep
credential redaction focused, especially in the copy prepared for an LLM, and
record any redactions or omissions. Honor the selected metadata/content mode.
Issue #23 is P2 for this workflow: a mode-contract and credential-redaction bug,
with no demonstrated external disclosure. Source retention in content mode is
useful behavior. Public fixture sanitization is a separate publication concern.

Inspect runs model evaluations and can route external agents' model traffic
through its Agent Bridge; ScanEval evaluates security scanners and harnesses,
some of which expose only partial native records. An
Inspect sample is the closest analogue to one ScanEval invocation, but the
objects and trust boundaries are not interchangeable.

## Changes following the comparison

The linked issues describe the original reproductions. The follow-up implementation
keeps ScanEval's bundle format and scanner-specific event contract:

- Metadata summaries retain tool structure and known file paths without copying
  arbitrary tool arguments. Content traces retain useful private source and tool
  evidence with focused credential-key redaction.
- Tiny native costs retain their decimal representation without dropping the
  response. Supported MCP result/error objects survive collection, and the
  TypeScript observer refuses array representations it cannot copy faithfully.
- A shared [trace reader](../src/scaneval/trace.py) validates saved wire records,
  retains readable events, and distinguishes missing, empty, malformed, and
  partially readable traces. Invalid records contribute to capture gaps.
  Duplicate IDs and producer-local sequence numbers remain recorded data;
  the reader does not invent global ordering or uniqueness requirements.
- Bounded native Read mappings require an explicit source snapshot binding,
  matching requested range and delivered bytes, and a later consuming assistant
  turn. Missing or contradictory evidence remains unknown. The mapping reports
  source correspondence, not model attention. [Collector contract](COLLECTORS.md).
- Full Semgrep scans retain an input inventory and explicit omissions so an
  unexamined control cannot earn quiet credit. Cancellation cleanup retires
  owned scanner processes while preserving the original interruption.
- Comparisons include effective deadlines and unambiguous configuration paths.
  Precision estimates bind to the scoped saved results so stale estimates are
  inconclusive after result content changes.

The local [investigation view and JSON export](INVESTIGATION.md) connect saved
invocations, targets, claims, supplied decision reasons, artifact bindings, and
validated trace events. Run/invocation/producer scopes remain explicit; unreadable,
missing, stale, and filtered evidence stay visible. The exported copy retains
private content only in content mode, records credential redactions and omissions,
and leaves source evidence unchanged. No export is sent to a model automatically.

The baseline table below explains what motivated these changes. Indexed cross-run
analysis and a live controller activity journal remain separate future work.

## Baseline implementation comparison

| Concern | Inspect AI | ScanEval at the reviewed baseline |
| --- | --- | --- |
| Capture boundary | Records native Inspect operations and external agents' model requests routed through its API bridge. Bridged model events contain conversation input, tool declarations, output, and available usage/errors. Tool conversation content is visible when reported by the agent; its own tool executions do not automatically produce `ToolEvent`s. [Bridge generation](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/agent/_bridge/util.py#L981), [tool boundary](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/agent/_bridge/util.py#L385) | Python and TypeScript observers record only boundaries a harness explicitly emits; Claude Code and Codex collectors import available native records. [Observer contract](OBSERVER_SDK.md), [collectors](COLLECTORS.md) |
| Event detail and correlation | Typed model and tool events carry inputs, outputs, usage, retries, errors, timing, and span IDs. Span begin/end events group work. [Model event](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/event/_model.py#L85), [tool event](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/event/_tool.py#L13), [spans](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/event/_span.py#L8) | A shared JSON schema defines 10 security-oriented event types, with `run_id`, `producer_id`, sequence, `parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, and `claim_id`. The payload is generic metadata/content, so provider usage and errors do not have typed, queryable fields across all adapters. [Trace schema](../schema/v2/trace-event.schema.json) |
| Finding lifecycle | Inspect's built-in events focus on model task execution and scoring. | Candidate, validation, filtering, and submission have dedicated event types and stable candidate/claim links. This is essential for explaining security scanner behavior. [Trace schema](../schema/v2/trace-event.schema.json) |
| Run and score linkage | An `EvalLog` contains configuration, results, stats, and samples; each sample contains messages, scores, events, usage, error, and attachments. [Log model](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_log.py#L1319) | The run manifest points to invocation bundles with `execution.json`, `result.json`, evaluation artifacts, and optional `trace/events.jsonl`. The event wire format has a run ID but no explicit invocation ID; its bundle supplies that context. [Runner](../src/scaneval/runner.py), [execution](../src/scaneval/execution.py) |
| Storage and access | `.eval` and JSON logs have a common API. `.eval` supports header and individual-sample reads, compressed storage, and attachment handling. [Log files](https://inspect.aisi.org.uk/eval-logs.html), [read API](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_file.py#L529) | Plain JSON documents plus JSONL trace are easy to inspect and preserve raw artifacts. There is no general indexed event reader. [Trace reader](../src/scaneval/execution.py) |
| Read-time validation | Sample events use Pydantic's `DiscriminatedEvent`, selected by event type; log and sample readers validate their models. [Event union](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/event/_event.py#L35), [sample model](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_log.py#L528) | Emitters validate their inputs, but bundle creation counts nonblank UTF-8 trace lines without parsing them. The context diagnostic checks selected fields rather than the complete wire contract. [Execution](../src/scaneval/execution.py), [diagnostics](../src/scaneval/diagnostics.py) |
| Human exploration | `inspect view` offers live run status, sample transcript, messages, scores, metadata, sorting, and filtering. [Log viewer](https://inspect.aisi.org.uk/log-viewer.html) | CLI progress and a static evaluation report exist; the report explicitly says no trace viewer is implemented. Context coverage has a separate diagnostic command. [Report](../src/scaneval/report.py), [diagnostic](DIAGNOSTICS.md) |
| Programmatic analysis | `evals_df`, `samples_df`, and `events_df` extract columns from stored logs, including model/tool usage and errors. `events_df(strict=False)` also returns import errors. [Event query](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/analysis/_dataframe/events/table.py#L46) | `scaneval diagnose context-coverage` joins `context.selection` spans to evaluator targets. Aggregate/compare operate on scoring artifacts, not a general event query API. [Diagnostic](../src/scaneval/diagnostics.py) |
| Runtime troubleshooting | Separate `inspect trace` logs retain recent evaluation actions and allow custom `trace_action` / `trace_message` calls without adding them to sample transcripts. [Tracing](https://inspect.aisi.org.uk/tracing.html) | Raw stdout/stderr, progress, execution notes, and `observer.error` events can explain failures, but there is no corresponding structured runner/adapter action trace. [Execution bundle](../src/scaneval/execution.py) |
| Capture completeness | Inspect has typed failure, retry, cancellation, and truncation data. This is different from a claim that an external scanner exposed every internal operation. [Model event](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/event/_model.py#L85) | ScanEval defines `complete`, `partial`, `redacted`, and `unavailable`, with dropped-event/gap accounting. These suit external scanner integrations; the defects below show places where implementation does not yet uphold the contract. [Observer contract](OBSERVER_SDK.md) |
| Data minimization | Structured model messages and tool arguments/results are retained. Raw provider request/response retention has separate controls: by default the first five calls per model and all errors are kept. [Logging configuration](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_log.py#L215), [retention](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_transcript.py#L780) | `off`/`metadata`/`content` modes and structured credential-key redaction provide explicit controls, but collector stringification currently bypasses those controls for some inputs. Labels remain evaluator-side. [Observer contract](OBSERVER_SDK.md), [collectors](COLLECTORS.md) |
| Untrusted rendering | `inspect view --no-trust-content` renders log content as plain text. This controls presentation; it does not remove sensitive data from the log. [Viewer](https://inspect.aisi.org.uk/log-viewer.html) | The static report escapes text and sets a restrictive content security policy. A future trace viewer needs equivalent protections for tool output, prompts, and source. [Report](../src/scaneval/report.py) |

### External-agent capture is an overlapping capability

Inspect's bridge preserves tool calls and results reported in model conversation
history, including Anthropic tool-error indicators. This gives it substantial
visibility into external agents. ScanEval's native collectors import the agent's
saved records, while the bridge intercepts model traffic; neither boundary alone
establishes every internal operation or actual tool execution duration.
[Responses conversion](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/agent/_bridge/responses_impl.py#L1334),
[Anthropic results](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/agent/_bridge/anthropic_api_impl.py#L591).

Inspect also supports model-event sinks for attribution to spans managed by an
external event stream. Its separate Inspect SWE agent integrations were not
audited here, so this comparison does not claim a limit on all possible Inspect
integrations. The bridge's default generation settings come from Inspect;
forwarding the client's settings is opt-in. Adopting a live proxy for ScanEval
would therefore require checking that it preserves the scanner behavior being
evaluated and recording the effective configuration.
[Event-sink contract and configuration](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/agent/_bridge/types.py#L196).

### What the viewer implementation makes possible

Inspect's frontend connects Transcript, Messages, Scoring, Activity, and Usage
within one sample; selecting an activity event opens its transcript. Its scoring
panel exposes the answer, score, explanation, reason, and metadata. Transcript
filters, event links, and retry history support investigation from an outcome
back to recorded activity.
[Sample display](https://github.com/meridianlabs-ai/ts-mono/blob/b07f814c50bc3fdeb141d2ba5b31a37d43a12b9d/apps/inspect/src/app/samples/SampleDisplay.tsx#L1038),
[score details](https://github.com/meridianlabs-ai/ts-mono/blob/b07f814c50bc3fdeb141d2ba5b31a37d43a12b9d/apps/inspect/src/app/samples/scores/SampleScoresGrid.tsx#L31),
[transcript panel](https://github.com/meridianlabs-ai/ts-mono/blob/b07f814c50bc3fdeb141d2ba5b31a37d43a12b9d/apps/inspect/src/app/samples/transcript/TranscriptPanel.tsx#L453),
[retry view](https://github.com/meridianlabs-ai/ts-mono/blob/b07f814c50bc3fdeb141d2ba5b31a37d43a12b9d/apps/inspect/src/app/samples/SampleRetriedErrors.tsx#L44).

ScanEval already requires reasons in evaluator decisions, but `render_report`
does not accept the decision document, execution record, or events. Exposing
those existing reasons and evidence links is a useful first product increment.
A generic event list alone would still leave the operator joining the outcome
to its evidence manually. [Decision schema](../src/scaneval/schemas/review-decisions.schema.json),
[report inputs](../src/scaneval/report.py).

## Reproduced ScanEval defects

These are implementation bugs, distinct from the feature gaps below. Each linked
issue includes a runnable synthetic reproduction, observed output, source links,
and acceptance criteria. No real credentials or live model calls were used.

| Priority | Defect and observed result | Tracking |
| --- | --- | --- |
| P2 mode correctness | **Metadata can contain source and credentials.** Both native collectors stringify arbitrary tool arguments into `metadata.input_summary` before key-based redaction. A synthetic `api_key` and source fragment survive in metadata mode, with no capture gap. Private content-mode traces should retain useful source; the defect is bypassing the selected mode and credential redaction. | [#23](https://github.com/Har1sh-k/scaneval/issues/23) |
| P2 | **Malformed trace content can appear complete.** A synthetic adapter writes `this is not JSON`; the saved execution says `success`, `model_requests: complete`, `events: 1`, and `capture_gap: false`. There are zero valid JSON events. No built-in producer incidence was established. | [#24](https://github.com/Har1sh-k/scaneval/issues/24) |
| P2 | **A small cost drops the final response.** Claude's `total_cost_usd=0.00005` violates the observer's numeric encoding policy, dropping the entire final `model.response`. Zero and `0.0001` controls work. The drop is counted, but response/usage data is lost. | [#25](https://github.com/Har1sh-k/scaneval/issues/25) |
| P2 | **Codex MCP results and error messages disappear.** Supported structured native result/error objects produce `tool.end` with `result_chars: 0` and no content, even in content mode. Status is retained, but the returned evidence or failure explanation is lost without a capture gap. The pinned official SDK source confirms these object shapes. | [#28](https://github.com/Har1sh-k/scaneval/issues/28) |
| P3 | **TypeScript array copying can silently change unsupported representations.** A sparse array becomes `[null]`, and extra array properties disappear, while capture remains complete with no gap. Dense arrays and explicit null work. Reject unsupported payloads consistently with the documented ordinary-object checks. | [#27](https://github.com/Har1sh-k/scaneval/issues/27) |
| P3 | **Fixture path scrubbing can retain identifying directories.** Unicode home-directory names survive partial path matching, and external paths resembling the placeholder root can remain unchanged. The sanitizer's final audit reports no problem in either synthetic case. This concerns an optional publication utility; no actual external disclosure was demonstrated. | [#36](https://github.com/Har1sh-k/scaneval/issues/36) |

A valid trace with no events in a particular category can still represent complete
observation of no activity. Validation must establish actual contradictions;
absence alone is not proof that the scanner did nothing or that capture failed.

## Product and architecture gaps

**Verified bounded native mappings (P2 enhancement).** The Claude collector marks
a partial-file Read as truncated and provides no verified source mapping. The
diagnostic correctly leaves such spans unknown under its current contract.
Synthetic tests demonstrate missing positive attribution, but do not verify the
delivered bytes against frozen source. Add that verification before claiming
positive coverage; a native offset, hash, or later assistant turn alone does not
establish source correspondence or model attention. Keep #18's conservative
guard. The verified scope of [#26](https://github.com/Har1sh-k/scaneval/issues/26)
is this integration enhancement.

1. **There is no run-level investigation path.** Operators must navigate from
   manifest to bundle to result and trace files, then manually join event IDs
   with submitted claims and scores. Inspect makes this a primary workflow in
   its viewer. The lack of a viewer is already acknowledged in ScanEval's
   report. [Report](../src/scaneval/report.py), [Inspect viewer](https://inspect.aisi.org.uk/log-viewer.html).

2. **Cross-run event questions require bespoke code.** ScanEval has context
   coverage diagnostics, but cannot readily ask “which model calls failed?”,
   “where did token use spike?”, or “which candidates were filtered before a
   missed target?” across saved invocations. Inspect's column extraction is a
   useful pattern; ScanEval's security-specific event types and capture status
   should remain the contract. [Inspect events dataframe](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/analysis/_dataframe/events/table.py#L46), [ScanEval diagnostic](DIAGNOSTICS.md).

3. **A heartbeat does not explain current activity.** Inspect publishes pending
   model events before calls finish and forwards transcript updates into its
   live sample logger. ScanEval reports that an invocation is still running;
   final bundle staging happens after the adapter returns. A controller-owned
   phase journal could show preparation, scan, import, and staging, plus
   failure/cancellation causes. It must label these as controller observations
   and leave opaque scanner internals unknown. [Inspect pending event](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/model/_model.py#L2001),
   [ScanEval heartbeat](../src/scaneval/runner.py),
   [scan boundary](../src/scaneval/execution.py).

4. **Scale is a later concern.** Inspect's indexed sample reads, compressed
   logs, and opt-in bounded in-memory transcript are useful patterns for large runs.
   Bounded mode is disabled unless `INSPECT_TRANSCRIPT_BOUNDED` is set at the
   reviewed revision; retained history backs evicted in-memory events. ScanEval's
   simple bundle and JSONL layout is appropriate while traces are modest;
   measure real trace sizes and viewer latency before changing storage.
   [Inspect log format](https://inspect.aisi.org.uk/eval-logs.html),
   [bounded transcript](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_transcript.py#L70).

## Implementation order

1. Repair the demonstrated capture defects: retain response data despite
   unrepresentable cost fields, preserve
   supported MCP results/errors, verify native source mappings, and reject lossy
   SDK payload copying. Keep rich evaluation content in content mode, arbitrary
   tool values out of metadata mode, and apply focused credential redaction.
   Later human and LLM analysis both depend on preserving the recorded evidence.
2. Add a shared trace validator for bundle ingestion and saved invocations. Stream JSONL;
   validate every event against the v2 schema and reconcile the declared event count.
   Preserve producer-local sequence numbers and IDs without inventing uniqueness
   or global-order guarantees that the wire contract does not provide. Check category-specific
   capture claims for contradictions where the adapter contract provides an
   independent expected count or lifecycle link; zero events alone must not
   refute a `complete` claim. Report malformed or missing data as a capture gap in a diagnostic
   result. Preserve readable positive evidence even when some lines fail.
   Keep run, invocation/bundle, and producer identity in join keys; identical
   call IDs in different producers must remain separate. Distinguish a missing
   trace, an empty valid trace, invalid records, and filters hiding all events.
3. Add an event query API or CLI export over saved bundles for RSI analysis.
   Use the validated reader as its source. Package relevant content, result and
   decision links, source revision, model/harness versions, effective settings,
   limits, and evaluation policy with their artifact identities. Preserve
   accepted, rejected, and unresolved judgments and their supplied reasons;
   identify those judgments separately from scanner allegations and observations.
   Check that scores, decisions, and precision estimates refer to the same saved
   evidence. Apply credential redaction to an export copy and describe what was
   redacted or omitted; preserve useful evaluation content and the original
   artifact bindings. Return import errors and capture gaps alongside readable
   rows. Missing usage remains unavailable, never zero; preserve whether a value
   describes a turn, attempt, or whole session.
4. Add a local, read-only trace view connected to the existing report or CLI.
   Show a run's invocations, statuses, capture completeness, and a time-ordered
   event list. Start investigation from a missed target or disputed claim. Show
   existing decision reasons, reviewer identity, and evidence bindings; link
   claims to lifecycle events and evaluation results. Filter by type, producer,
   call, candidate, and claim. Render untrusted
   content safely and respect `metadata` versus `content` mode. Label import
   time separately from native source time and source order. Never calculate
   scanner latency from timestamps assigned while importing a transcript;
   preserve unknown durations where native evidence supplies no measurement.
   Missing links must say `not linked` or `not captured`. A missed target with
   no recorded explanation must not acquire a fabricated one. Preserve the
   distinction between supplied evaluator judgments and mechanically checked
   evidence; source inclusion does not prove model attention.
   The concrete first increment is tracked in
   [#43](https://github.com/Har1sh-k/scaneval/issues/43).
5. Add persisted controller phase activity before offering a live investigation
   view. Record start, completion, error, and interruption with stable invocation
   links. Display the last observed activity and measured elapsed time; do not
   infer model progress from a process heartbeat. Treat unfinished actions as
   unknown/interrupted until reconciled.

The first milestone is complete when one failed, one partial, and one complete
fixture can be exported with their recorded evidence, effective configuration,
decision reasons, artifact bindings, and explicit capture gaps. An operator or
downstream LLM should be able to follow each available claim-to-event link and
understand why a score or diagnostic did or did not use the observation.

## Verification and limits

- The original seven observability reproductions ran successfully. Subsequent
  adversarial review retained six defect claims and reclassified #26 as a
  verified-mapping enhancement; reproducing its current unknown result does
  not prove the diagnostic violates its contract.
- The TypeScript SDK suite passed: 43 tests.
- The full Python baseline reported 3,595 passed, 65 failed, and 6 skipped.
  The failures comprise 46 harness `tsx` IPC permission errors, one missing
  fixture-driver `tsx` dependency, 15 real-Semgrep cases (startup reproduced
  `ca-certs: empty trust anchors`), two other permission errors, and one macOS
  `xcrun_db` scratch-directory expectation.
  After installing the pinned fixture dependency and rerunning with the required
  local permissions, all 65 previously failing tests passed. These are a baseline
  plus a targeted rerun, not a single clean full-suite run. None of those initial
  environment failures is reported as a product defect.
- The real Docker integration suite passed locally: 15 tests. CI for the reviewed
  commit also passed on Python 3.11 and 3.13, including its Docker job.
  [CI run](https://github.com/Har1sh-k/scaneval/actions/runs/38499177306).
- An installed wheel was checked outside the checkout: all 26 packaged schemas
  loaded, demo/replay/report generation passed, and replay matched the saved
  evaluation byte-for-byte.
- Inspect behavior is derived from pinned source and official documentation.
  No live provider comparison, performance measurement, or GUI runtime test was
  performed. The table and reproductions above describe the pinned baseline; subsequent
  implementation changes are tracked by the linked issues.

Inspect's live event buffer is not a guarantee of crash-proof persistence, and
its transcript subscribers can fail. At this revision its live SQLite buffer
uses `synchronous=OFF`; subscriber exceptions are logged and suppressed.
ScanEval should retain explicit capture-gap accounting when adopting these
patterns. [Live database](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_recorders/buffer/database.py#L1189),
[subscriber handling](https://github.com/UKGovernmentBEIS/inspect_ai/blob/a699376315c95b6410f5aec01af37c8dec452aea/src/inspect_ai/log/_transcript.py#L780).
