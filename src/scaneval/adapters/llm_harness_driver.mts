// ScanEval driver for the securevibes-agent / Fieldglass engine family.
//
// It runs the harness's own engine (runRuntimeScan) unchanged and observes it through
// whichever observation surfaces that harness build exports. There are two, both optional:
//
//   * the runner hooks (`PI_RUNNER_HOOKS_VERSION`), which report every CLI attempt from
//     inside the harness's own retry loop, and carry the claude json result object with
//     them (token usage, the CLI's cost estimate, the served model id);
//   * the engine observer (`HARNESS_OBSERVER_VERSION`), which reports the code the engine
//     placed in each prompt and the life of every finding candidate.
//
// Neither is assumed. Each is feature-detected and recorded in the output as `hooks`, and a
// build that exports neither is observed exactly as before: one request/response pair per
// logical call, the harness's own progress notes as self-reported context, and the findings
// in the returned summary. What cannot be seen is therefore a property of the run and is
// declared per run in `trace.unavailable` rather than being a fixed list.
//
// Invoked by scaneval.adapters.llm_harness with the harness's own tsx:
//   <harness>/node_modules/.bin/tsx llm_harness_driver.mts --config <driver-config.json>

import { appendFileSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const DRIVER_VERSION = "2.2.0";

interface DriverConfig {
  harness_root: string;
  engine_entry: string;
  runner_entry: string;
  mock_entry: string;
  observer_sdk: string;
  repo_path: string;
  mode: "bootstrap" | "pr" | "batch";
  model: string;
  llm_max_files?: number;
  llm_timeout_ms?: number;
  qmd_profile?: "full" | "lite";
  specialist_ids?: string[];
  base_ref?: string;
  head_ref?: string;
  runner: "default" | "mock";
  trace_mode: "off" | "metadata" | "content";
  trace_path?: string;
  run_id: string;
  producer_id: string;
  output_path: string;
  progress_path: string;
  flush_timeout_ms: number;
}

interface PiMeta { invocationId?: string; stage?: string }
// Only the fields this driver reads off `claude -p --output-format json`, as the harness
// runner maps them. A field the CLI did not print is null there and stays null here.
interface ClaudeStructured {
  subtype?: string | null;
  isError?: boolean | null;
  numTurns?: number | null;
  sessionId?: string | null;
  durationApiMs?: number | null;
  totalCostUsd?: number | null;
  usage?: Record<string, unknown> | null;
  modelUsage?: Record<string, unknown> | null;
}
type PiResult = {
  code: number; stdout: string; stderr: string;
  binary?: string; outputFormat?: "text" | "json";
  structured?: ClaudeStructured | null; structuredParseError?: string;
};
type PiInvocation = { args?: string[]; request?: unknown; cwd: string; timeoutMs: number; env: NodeJS.ProcessEnv; meta?: PiMeta };
type PiRunner = { runPi(options: PiInvocation): Promise<PiResult> };

// PiAttemptStart / PiAttemptRecord, as much of each as this driver reads.
interface AttemptStart {
  invocationId?: string; stage?: string;
  attempt: number; maxAttempts: number;
  binary: string; modelRequested: string | null; thinking: string | null;
  outputFormat: "text" | "json";
  promptChars: number; timeoutMs: number; startedAt: string;
}
interface AttemptRecord extends AttemptStart {
  durationMs: number;
  code: number | null;
  error?: string;
  stdoutChars: number; stderrChars: number;
  failureKind?: string;
  willRetry: boolean; retryDelayMs?: number;
  structured?: ClaudeStructured | null;
  structuredParseError?: string;
}

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

function nowIso(): string {
  return new Date().toISOString();
}

function gitHead(root: string): { head: string | null; dirty: boolean | null } {
  try {
    const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const status = execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim();
    return { head, dirty: status.length > 0 };
  } catch {
    return { head: null, dirty: null };
  }
}

// execCommand's timeout and abort messages embed the whole argv, and the argv carries the
// prompt, which carries the source under analysis. Metadata must never hold content, so the
// argv is cut here the way the harness runner cuts it on its own attempt records; this is the
// fallback for a message the driver catches itself, where no attempt record exists to read.
const ARGV_BEARING_ERROR = /^(Command (?:timed out|aborted): \S+)\s[\s\S]*$/;
const MAX_ERROR_CHARS = 200;

function safeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  const withoutArgv = raw.replace(ARGV_BEARING_ERROR, "$1");
  return withoutArgv.length > MAX_ERROR_CHARS ? `${withoutArgv.slice(0, MAX_ERROR_CHARS)}...` : withoutArgv;
}

// Both emitters store only the numbers the two languages write identically: a safe integer, or
// a non-integral value of at least 1e-4 in magnitude. Anything else is refused, and a refused
// event is a whole lost observation rather than one missing field, so every number that goes
// into metadata passes through here and becomes null instead of taking its event down.
const MIN_PLAIN_DECIMAL = 1e-4;

function wireNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (Number.isInteger(value)) return Number.isSafeInteger(value) ? value + 0 : null;
  return Math.abs(value) >= MIN_PLAIN_DECIMAL ? value : null;
}

const USAGE_KEYS = ["input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"] as const;

/** The four token counts, or null when the CLI reported none of them. */
function usageFrom(structured: ClaudeStructured | null | undefined): Record<string, number | null> | null {
  const usage = structured?.usage;
  if (!usage || typeof usage !== "object") return null;
  const counts: Record<string, number | null> = {};
  let reported = false;
  for (const key of USAGE_KEYS) {
    const value = wireNumber((usage as Record<string, unknown>)[key]);
    counts[key] = value;
    if (value !== null) reported = true;
  }
  return reported ? counts : null;
}

/**
 * The served model id, and only when the CLI named exactly one.
 *
 * `modelUsage` is keyed by served model. Two keys would need a per-turn split the result
 * object does not carry, so the driver reports none rather than picking one of them.
 */
function modelServed(structured: ClaudeStructured | null | undefined): string | null {
  const modelUsage = structured?.modelUsage;
  if (!modelUsage || typeof modelUsage !== "object") return null;
  const keys = Object.keys(modelUsage);
  return keys.length === 1 ? keys[0] ?? null : null;
}

interface InvocationView {
  model: string | null;
  thinking: string | null;
  promptChars: number;
  route: string;
  content: Record<string, unknown>;
}

// securevibes-agent hands the runner pi-style argv with the prompt last; Fieldglass hands it a
// structured ModelRequest whose prompt travels on stdin. Describe either without changing it.
function describeInvocation(options: Record<string, unknown>, resolveBinary?: (args: string[]) => string): InvocationView {
  const args = Array.isArray(options.args) ? (options.args as string[]) : null;
  if (args) {
    const flag = (name: string): string | null => {
      const index = args.indexOf(name);
      return index === -1 ? null : args[index + 1] ?? null;
    };
    return {
      model: flag("--model"),
      thinking: flag("--thinking"),
      promptChars: args.length > 0 ? (args[args.length - 1] ?? "").length : 0,
      route: resolveBinary ? resolveBinary(args) : "unknown",
      content: { args },
    };
  }
  const request = (options.request ?? {}) as { route?: { driver?: string; model?: string }; effort?: string; prompt?: string };
  const route = request.route ?? {};
  return {
    model: route.model ?? null,
    thinking: request.effort ?? null,
    promptChars: (request.prompt ?? "").length,
    route: route.driver ?? "unknown",
    content: { request: { route: { driver: route.driver ?? null, model: route.model ?? null }, effort: request.effort ?? null, prompt: request.prompt ?? null } },
  };
}

/** One logical model invocation: what the attempts of that call are joined against. */
interface CallState {
  callId: string;
  view: InvocationView;
  route: string;
  /** The `willRetry: false` record, stashed for the wrapper to pair with the returned result. */
  final: AttemptRecord | null;
}

function suppliedSpan(span: Record<string, unknown>): Record<string, unknown> {
  return {
    path: String(span.path ?? ""),
    start_line: wireNumber(span.startLine),
    end_line: wireNumber(span.endLine),
    chars: wireNumber(span.chars),
    sha256: String(span.sha256 ?? ""),
    truncated: span.truncated === true,
    original_chars: wireNumber(span.originalChars),
    // How many of `chars` are a synthetic truncation marker rather than supplied source, when
    // the engine says. Null means it did not, not that there was no marker.
    marker_chars: wireNumber(span.markerChars),
    role: String(span.role ?? "other"),
    // Absent on the record means the line numbers are real file positions; false means the
    // supplied text could not be located and the lines are 1..N of that text instead. A
    // consumer joining spans against source locations must not treat those as file positions,
    // so the flag is always present here rather than only when it is false.
    location_known: span.locationKnown !== false,
  };
}

async function main(): Promise<void> {
  const configPath = argValue("config");
  if (!configPath) throw new Error("--config <path> is required");
  const config = JSON.parse(readFileSync(configPath, "utf8")) as DriverConfig;
  const startedAt = nowIso();
  const started = Date.now();

  const engineModule = await import(pathToFileURL(join(config.harness_root, config.engine_entry)).href);
  const runnerModule = await import(pathToFileURL(join(config.harness_root, config.runner_entry)).href);
  const observerModule = await import(pathToFileURL(config.observer_sdk).href);

  // Capability detection, once, by what the harness build actually exports. Every branch below
  // reads these two and nothing else, so an older harness takes the pre-hooks path in all of
  // them rather than in the ones somebody remembered.
  const runnerHooks: number | null = runnerModule.PI_RUNNER_HOOKS_VERSION ?? null;
  const engineHooks: number | null = engineModule.HARNESS_OBSERVER_VERSION ?? null;
  const resolveBinary: ((args: string[]) => string) | undefined = runnerModule.resolveRunnerBinary;

  let eventsWritten = 0;
  const observer = new observerModule.Observer({
    mode: config.trace_mode,
    runId: config.run_id,
    producerId: config.producer_id,
    sink: config.trace_mode === "off" || !config.trace_path
      ? undefined
      : observerModule.createJsonlSink((line: string) => {
        appendFileSync(config.trace_path as string, line);
        eventsWritten += 1;
      }),
  });

  let modelCalls = 0;
  let modelFailures = 0;
  let modelAttempts = 0;
  // Which CLI actually served each call. The tool policy differs by route, and neither
  // route's tool dispatch happens in this process, so this records what was asked for,
  // never what the CLI did with it.
  const observedRoutes = new Set<string>();
  const calls = new Map<string, CallState>();
  // Which invocations were seen from each side. Not every model call is instrumented -- the
  // threat planner reports no context, and only some specialists do -- so how many were is
  // counted here rather than described in a sentence that would go stale as the harness
  // instruments more of itself.
  const modelCallIds = new Set<string>();
  const contextCallIds = new Set<string>();
  const usageTotals: Record<string, number> = {};
  let usageObserved = false;
  let costTotal: number | null = null;
  const modelsServed = new Set<string>();

  // Summed over every attempt the runner reported, failed attempts included: a retried attempt
  // still spent its tokens. Nothing here is a bill; it is the CLI's own accounting of its call.
  function accumulate(record: AttemptRecord): void {
    const usage = usageFrom(record.structured);
    if (usage) {
      for (const [key, value] of Object.entries(usage)) {
        if (value === null) continue;
        usageTotals[key] = (usageTotals[key] ?? 0) + value;
        usageObserved = true;
      }
    }
    const cost = record.structured?.totalCostUsd;
    if (typeof cost === "number" && Number.isFinite(cost)) costTotal = (costTotal ?? 0) + cost;
    const served = modelServed(record.structured);
    if (served) modelsServed.add(served);
  }

  function attemptId(callId: string, attempt: number): string {
    return `${callId}/attempt-${attempt}`;
  }

  /** The structured half of a response event: what the claude json result object said. */
  function structuredMetadata(structured: ClaudeStructured | null | undefined): Record<string, unknown> {
    const cost = structured?.totalCostUsd;
    const wired = wireNumber(cost);
    const usage = usageFrom(structured);
    return {
      // The counts, not the envelope around them. A result object that carried no usage is a
      // run with no usage to read, and saying otherwise would make an absent count look
      // measured to anything reading this field before the one below it.
      usage_available: usage !== null,
      usage,
      cost_usd_cli_reported: wired,
      // A cost the trace cannot carry as a number (the shared plain-decimal window stops at
      // 1e-4) is kept verbatim as text rather than rounded to zero or dropped in silence.
      ...(wired === null && typeof cost === "number" && Number.isFinite(cost)
        ? { cost_usd_cli_reported_text: String(cost) }
        : {}),
      num_turns: wireNumber(structured?.numTurns),
      session_id: structured?.sessionId ?? null,
      result_subtype: structured?.subtype ?? null,
      is_error: typeof structured?.isError === "boolean" ? structured.isError : null,
      duration_api_ms: wireNumber(structured?.durationApiMs),
      model_served: modelServed(structured),
    };
  }

  // One start and one end per CLI attempt, from inside the harness's own retry loop. The hooks
  // are called synchronously and are never awaited by the runner, so they emit without
  // awaiting: the emitter takes its sequence number at the call, which keeps the recorded order
  // the order the attempts happened in, and the flush at the end settles the writes.
  const piRunnerHooks = {
    onAttemptStart(record: AttemptStart): void {
      modelAttempts += 1;
      const state = record.invocationId ? calls.get(record.invocationId) : undefined;
      const correlated = state !== undefined;
      void observer.emit({
        type: "model.request",
        // Correlated or not, the request itself was fully observed; an attempt the driver
        // cannot tie back to a call it wrapped is reported as the partial observation it is.
        capture_status: correlated ? "complete" : "partial",
        ...(state ? { call_id: state.callId, attempt_id: attemptId(state.callId, record.attempt) } : {}),
        metadata: {
          source: "harness_runner_hook",
          // The mock runner spawns no CLI, so the binary the runner resolved off the argv
          // would name a process that never existed.
          route: config.runner === "mock" ? "mock" : state?.route ?? record.binary ?? "unknown",
          model_requested: record.modelRequested,
          thinking: record.thinking,
          stage: record.stage ?? null,
          attempt: record.attempt,
          max_attempts: record.maxAttempts,
          retries_observable: true,
          prompt_chars: wireNumber(record.promptChars),
          timeout_ms: wireNumber(record.timeoutMs),
          output_format: record.outputFormat,
          ...(correlated ? {} : { correlation: "missing_invocation_id" }),
        },
        ...(state ? { content: state.view.content } : {}),
      });
    },
    onAttemptEnd(record: AttemptRecord): void {
      accumulate(record);
      const state = record.invocationId ? calls.get(record.invocationId) : undefined;
      if (!record.willRetry) {
        // The last attempt's response is emitted by the wrapper instead, once the call has
        // settled: only the returned result carries stdout and stderr, and this record carries
        // their lengths. Stashing it is what lets the two halves be reported as one event.
        if (state) state.final = record;
        return;
      }
      void observer.emit({
        type: "model.response",
        // A retried attempt's stdout is not handed back through the runner, so this event
        // reports the attempt without the text it produced.
        capture_status: "partial",
        ...(state ? { call_id: state.callId, attempt_id: attemptId(state.callId, record.attempt) } : {}),
        duration_ms: Math.max(0, Math.round(record.durationMs)),
        metadata: {
          source: "harness_runner_hook",
          route: config.runner === "mock" ? "mock" : state?.route ?? record.binary ?? "unknown",
          model_requested: record.modelRequested,
          stage: record.stage ?? null,
          attempt: record.attempt,
          will_retry: true,
          retry_delay_ms: wireNumber(record.retryDelayMs),
          failure_kind: record.failureKind ?? null,
          exit_code: record.code,
          error: record.error ?? null,
          output_format: record.outputFormat,
          stdout_chars: wireNumber(record.stdoutChars),
          stderr_chars: wireNumber(record.stderrChars),
          ...structuredMetadata(record.structured),
          ...(record.structuredParseError ? { structured_parse_error: record.structuredParseError } : {}),
          ...(state ? {} : { correlation: "missing_invocation_id" }),
        },
      });
    },
  };

  const mockRunner = (): Promise<PiRunner> =>
    import(pathToFileURL(join(config.harness_root, config.mock_entry)).href)
      .then((module) => module.createDeterministicTestLlmRunner() as PiRunner);

  const baseRunner: PiRunner = config.runner === "mock"
    // The mock route goes through the same retry wrapper so it exercises the same attempt
    // events; one attempt, because a deterministic runner has nothing to retry.
    ? (runnerHooks === null
      ? await mockRunner()
      : runnerModule.createRetryingPiRunner(await mockRunner(), { maxAttempts: 1 }, piRunnerHooks))
    : (runnerHooks === null
      ? runnerModule.createDefaultPiRunner()
      // json is what makes usage, the cost estimate and the served model id observable at all;
      // the runner still hands the engine exactly the text the run would have printed.
      : runnerModule.createDefaultPiRunner({ hooks: piRunnerHooks, claudeOutputFormat: "json" }));

  /** Today's response event: one per logical call, with nothing below the runner boundary. */
  async function emitUnhookedResponse(state: CallState, result: PiResult | null, error: unknown, elapsed: number): Promise<void> {
    if (result === null) {
      await observer.emit({
        type: "model.response",
        capture_status: "partial",
        call_id: state.callId,
        duration_ms: elapsed,
        metadata: { source: "driver_runner_wrapper", model_requested: state.view.model,
                    exception: safeErrorMessage(error) },
      });
      return;
    }
    await observer.emit({
      type: "model.response",
      capture_status: "complete",
      call_id: state.callId,
      duration_ms: elapsed,
      metadata: {
        source: "driver_runner_wrapper",
        model_requested: state.view.model,
        exit_code: result.code,
        stdout_chars: result.stdout.length,
        stderr_chars: result.stderr.length,
        usage_available: false,
      },
      content: { stdout: result.stdout, stderr: result.stderr },
    });
  }

  /** The final attempt's response, paired with the stashed record that describes it. */
  async function emitHookedResponse(state: CallState, result: PiResult | null, error: unknown, elapsed: number): Promise<void> {
    const record = state.final;
    await observer.emit({
      type: "model.response",
      // Complete needs both halves: the attempt record that describes the attempt and the
      // result that carries its text. A call that threw has no text to record even though the
      // record says how much there was, and a call whose last attempt was never reported has
      // no attempt to name, so it carries no attempt id either. Both are partial.
      capture_status: record && result ? "complete" : "partial",
      call_id: state.callId,
      ...(record ? { attempt_id: attemptId(state.callId, record.attempt) } : {}),
      // The attempt's own duration, as the runner measured it, so every attempt event in a
      // run is the same measurement. The wrapper's elapsed time spans the earlier attempts and
      // the backoffs between them, which is a different quantity and is recorded as one.
      duration_ms: record ? Math.max(0, Math.round(record.durationMs)) : elapsed,
      metadata: {
        source: "harness_runner_hook",
        call_elapsed_ms: elapsed,
        route: state.route,
        model_requested: record?.modelRequested ?? state.view.model,
        stage: record?.stage ?? null,
        attempt: record?.attempt ?? null,
        attempt_record: record ? "paired" : "missing",
        will_retry: record ? record.willRetry : null,
        retry_delay_ms: wireNumber(record?.retryDelayMs),
        failure_kind: record?.failureKind ?? null,
        exit_code: result ? result.code : record?.code ?? null,
        // The runner's own message wins: it is argv-stripped, capped, and specific about the
        // attempt (an aborted backoff says so, where the thrown error only says the invocation
        // was aborted). A message this driver caught itself is stripped here for the same
        // reason the runner strips its own: the argv carries the prompt.
        error: record?.error ?? (error === null ? null : safeErrorMessage(error)),
        output_format: record?.outputFormat ?? null,
        stdout_chars: result ? result.stdout.length : wireNumber(record?.stdoutChars),
        stderr_chars: result ? result.stderr.length : wireNumber(record?.stderrChars),
        ...structuredMetadata(result ? result.structured ?? record?.structured : record?.structured),
        ...(record?.structuredParseError ? { structured_parse_error: record.structuredParseError } : {}),
      },
      ...(result ? { content: { stdout: result.stdout, stderr: result.stderr } } : {}),
    });
  }

  const observedRunner: PiRunner = {
    async runPi(options) {
      modelCalls += 1;
      const minted = `call-${modelCalls}`;
      const meta = (options.meta ?? {}) as PiMeta;
      // The engine's own id when it tagged the call, so a context.selection event and the model
      // events of the same invocation share one call_id; the driver's own id when it did not.
      const callId = meta.invocationId ?? minted;
      const view = describeInvocation(options as unknown as Record<string, unknown>, resolveBinary);
      const route = config.runner === "mock" ? "mock" : view.route;
      observedRoutes.add(route);
      const state: CallState = { callId, view, route, final: null };
      calls.set(callId, state);
      modelCallIds.add(callId);
      // Injected so an untagged call still arrives at the hooks with an id to join on. The
      // runners ignore meta; nothing the engine decides changes because of it.
      const invocation = meta.invocationId === undefined ? { ...options, meta: { ...meta, invocationId: callId } } : options;
      const began = Date.now();
      if (runnerHooks === null) {
        await observer.emit({
          type: "model.request",
          capture_status: "complete",
          call_id: callId,
          metadata: {
            // This driver's own wrapper around the harness runner, which is all an older
            // harness build exposes: one observation per logical call, taken from outside.
            source: "driver_runner_wrapper",
            model_requested: view.model,
            thinking: view.thinking,
            route,
            prompt_chars: view.promptChars,
            timeout_ms: options.timeoutMs,
            retries_observable: false,
          },
          content: view.content,
        });
      }
      try {
        const result = await baseRunner.runPi(invocation);
        if (result.code !== 0) modelFailures += 1;
        const elapsed = Date.now() - began;
        if (runnerHooks === null) await emitUnhookedResponse(state, result, null, elapsed);
        else await emitHookedResponse(state, result, null, elapsed);
        return result;
      } catch (error) {
        modelFailures += 1;
        const elapsed = Date.now() - began;
        if (runnerHooks === null) await emitUnhookedResponse(state, null, error, elapsed);
        else await emitHookedResponse(state, null, error, elapsed);
        throw error;
      } finally {
        calls.delete(callId);
      }
    },
  };

  interface SubmittedRecord {
    candidateIds?: string[]; findingId?: string; filePath?: string;
    vulnerabilityClass?: string; severity?: string; status?: string; disposition?: string;
  }
  const submittedRecords: SubmittedRecord[] = [];
  let scanComplete: Record<string, unknown> | null = null;
  const observerRecords = {
    context_selection: 0, finding_candidate: 0, finding_validation: 0,
    finding_filtered: 0, finding_submitted: 0,
  };

  // The engine calls these synchronously at the boundary and never awaits them, exactly as the
  // runner hooks are called, so they emit the same way. Nothing here can throw into the scan.
  const harnessObserver = {
    onContextSupplied(record: Record<string, unknown>): void {
      observerRecords.context_selection += 1;
      if (typeof record.invocationId === "string") contextCallIds.add(record.invocationId);
      const spans = (Array.isArray(record.spans) ? record.spans : []) as Record<string, unknown>[];
      void observer.emit({
        type: "context.selection",
        // The engine reports the whole set it supplied for this invocation, which is the one
        // thing a derived self-report cannot claim.
        capture_status: "complete",
        ...(typeof record.invocationId === "string" ? { call_id: record.invocationId } : {}),
        metadata: {
          source: "harness_emitted",
          stage: record.stage ?? null,
          prompt_chars: wireNumber(record.promptChars),
          span_count: spans.length,
          spans: spans.map(suppliedSpan),
          truncated_spans: wireNumber(record.truncatedSpans),
          omitted_paths: Array.isArray(record.omittedPaths) ? record.omittedPaths : [],
          hypothesis_id: record.hypothesisId ?? null,
          specialist_id: record.specialistId ?? null,
        },
      });
    },
    onFindingCandidate(record: Record<string, unknown>): void {
      observerRecords.finding_candidate += 1;
      void observer.emit({
        type: "finding.candidate",
        capture_status: "complete",
        candidate_id: String(record.candidateId ?? ""),
        ...(typeof record.invocationId === "string" ? { call_id: record.invocationId } : {}),
        metadata: {
          source: "harness_emitted",
          stage: record.stage ?? null,
          file_path: record.filePath ?? null,
          line_numbers: Array.isArray(record.lineNumbers) ? record.lineNumbers : null,
          vulnerability_class: record.vulnerabilityClass ?? null,
          severity: record.severity ?? null,
          confidence: wireNumber(record.confidence),
          // The model supplied a class or severity outside the vocabulary. The value is
          // withheld by the engine (it can carry source or a secret); that it existed is not.
          raw_value_withheld: record.rawValueWithheld === true,
        },
      });
    },
    onFindingValidation(record: Record<string, unknown>): void {
      observerRecords.finding_validation += 1;
      void observer.emit({
        type: "finding.validation",
        capture_status: "complete",
        candidate_id: String(record.candidateId ?? ""),
        ...(typeof record.invocationId === "string" ? { call_id: record.invocationId } : {}),
        metadata: {
          source: "harness_emitted",
          stage: record.stage ?? null,
          verdict: record.verdict ?? null,
          reason: record.reason ?? null,
          // The engine sanitizes and caps this, and says so when it withheld one because the
          // explanation could quote source. Both states are carried; neither is invented.
          detail: record.detail ?? null,
          detail_omitted: record.detailOmitted === true,
        },
      });
    },
    onFindingFiltered(record: Record<string, unknown>): void {
      observerRecords.finding_filtered += 1;
      void observer.emit({
        type: "finding.filtered",
        capture_status: "complete",
        candidate_id: String(record.candidateId ?? ""),
        metadata: {
          source: "harness_emitted",
          stage: record.stage ?? null,
          reason: record.reason ?? null,
          merged_into: record.mergedIntoCandidateId ?? null,
        },
      });
    },
    // A later reading of the same counter the summary carries, taken after the summary was
    // built, plus what the engine dropped for want of a file path to attribute it to. Optional:
    // a harness that does not call it leaves the field null, which is not a reading of zero.
    onScanComplete(record: { hookFailures?: number; unattributablePayloads?: number }): void {
      scanComplete = {
        hook_failures: wireNumber(record.hookFailures),
        unattributable_payloads: wireNumber(record.unattributablePayloads),
      };
    },
    onFindingSubmitted(record: SubmittedRecord): void {
      observerRecords.finding_submitted += 1;
      // Buffered rather than emitted here: the engine reports these once the record set is
      // final, as a block, and the component, scanner sources and confidence of the written
      // record exist only in the summary the same call is about to return. Emitting after the
      // scan joins the two without claiming either says something the other does not.
      submittedRecords.push(record);
    },
  };

  let progressNotes = 0;
  const progressReporter = (note: string): void => {
    progressNotes += 1;
    appendFileSync(config.progress_path, `${nowIso()} ${note}\n`);
    // With the engine reporting the context it actually supplied, the harness's description of
    // itself would be a second, weaker event about the same selection, counted twice.
    if (engineHooks === null && /(^|\s)file=/.test(note)) {
      void observer.emit({
        type: "context.selection",
        capture_status: "partial",
        metadata: { source: "harness_self_report", note },
      });
    }
  };

  let summary: unknown = null;
  let failure: { name: string; message: string } | null = null;
  try {
    summary = await engineModule.runRuntimeScan({
      repoPath: config.repo_path,
      mode: config.mode,
      analysisMode: "llm",
      llmModel: config.model,
      llmRunner: observedRunner,
      progressReporter,
      ...(engineHooks === null ? {} : { observer: harnessObserver }),
      ...(config.qmd_profile ? { qmdProfile: config.qmd_profile } : {}),
      ...(typeof config.llm_max_files === "number" ? { llmMaxFiles: config.llm_max_files } : {}),
      ...(typeof config.llm_timeout_ms === "number" ? { llmTimeoutMs: config.llm_timeout_ms } : {}),
      ...(config.specialist_ids ? { specialistIds: config.specialist_ids } : {}),
      ...(config.base_ref ? { baseRef: config.base_ref } : {}),
      ...(config.head_ref ? { headRef: config.head_ref } : {}),
    });
  } catch (error) {
    failure = { name: error instanceof Error ? error.name : "Error", message: error instanceof Error ? error.message : String(error) };
  }

  const record = (summary ?? {}) as { newFindings?: Array<Record<string, unknown>>; updatedFindings?: Array<Record<string, unknown>>; observer?: { hookFailures?: number } };
  const writtenFindings = [...(record.newFindings ?? []), ...(record.updatedFindings ?? [])];
  // Which of the two accounts of the submitted set this run emitted. The engine's own records
  // are richer and are used whenever it reported any, but a build that exports the observer
  // version and reports none for a summary that does hold findings has not told us there were
  // none: the summary loop stands in, so the category is not silently empty while the capture
  // matrix calls it complete. Which one ran is named in the output rather than inferred.
  const submittedSource = engineHooks !== null && (submittedRecords.length > 0 || writtenFindings.length === 0)
    ? "engine_records"
    : "summary";
  if (submittedSource === "summary") {
    for (const [stage, findings] of [["new", record.newFindings ?? []], ["updated", record.updatedFindings ?? []]] as const) {
      for (const finding of findings) {
        const id = String(finding.id ?? "");
        if (!id) continue;
        await observer.emit({
          type: "finding.submitted",
          capture_status: "complete",
          candidate_id: id,
          claim_id: id,
          metadata: {
            // Read off the summary the engine returned, not reported by the engine as it
            // submitted each record: the same findings, a weaker account of them.
            source: "harness_summary",
            stage,
            vulnerability_class: finding.vulnerabilityClass ?? null,
            severity: finding.severity ?? null,
            component: finding.component ?? null,
            file_path: finding.filePath ?? null,
            scanner_sources: finding.scannerSources ?? null,
            confidence: wireNumber(finding.confidence),
            status: finding.status ?? null,
          },
        });
      }
    }
  } else {
    const written = new Map<string, Record<string, unknown>>();
    for (const finding of writtenFindings) {
      const id = String(finding.id ?? "");
      if (id) written.set(id, finding);
    }
    for (const submitted of submittedRecords) {
      const id = String(submitted.findingId ?? "");
      // A record with no id links to nothing; the importer counts that as loss, not this.
      if (!id) continue;
      const finding = written.get(id) ?? {};
      await observer.emit({
        type: "finding.submitted",
        capture_status: "complete",
        // The harness's own finding id, so the claim linkage the importer builds is unchanged.
        candidate_id: id,
        claim_id: id,
        metadata: {
          source: "harness_emitted",
          stage: submitted.disposition ?? null,
          disposition: submitted.disposition ?? null,
          // Empty for a record the engine updated on its own (a TTL expiry, a revalidation, a
          // rename): no model candidate is behind it, which is what the empty list says.
          candidate_ids: Array.isArray(submitted.candidateIds) ? submitted.candidateIds : [],
          vulnerability_class: finding.vulnerabilityClass ?? submitted.vulnerabilityClass ?? null,
          severity: finding.severity ?? submitted.severity ?? null,
          component: finding.component ?? null,
          file_path: finding.filePath ?? submitted.filePath ?? null,
          scanner_sources: finding.scannerSources ?? null,
          confidence: wireNumber(finding.confidence),
          status: finding.status ?? submitted.status ?? null,
        },
      });
    }
  }

  let flushTimedOut = false;
  await Promise.race([
    observer.flush(),
    new Promise<void>((resolve) => setTimeout(() => { flushTimedOut = true; resolve(); }, config.flush_timeout_ms).unref()),
  ]);

  let packageVersion: string | null = null;
  try {
    packageVersion = JSON.parse(readFileSync(join(config.harness_root, "package.json"), "utf8")).version ?? null;
  } catch {
    packageVersion = null;
  }

  // Model invocations the engine reported no context for. Measured, not assumed: which stages
  // are instrumented is the harness's business and changes as it instruments more of itself.
  const untaggedCalls = [...modelCallIds].filter((id) => !contextCallIds.has(id)).length;
  // What this run could not see, for this harness build. Each entry is a category nothing was
  // observed in; none of them is evidence that the thing did not happen.
  const unavailable = [
    "tool.start",
    "tool.end",
    ...(engineHooks === null ? ["finding.candidate"] : []),
    // The consensus judge is the only validation stage, and it runs in pr mode. A bootstrap run
    // has no validation stage at all, which is a different statement from not seeing one.
    ...(engineHooks === null
      ? ["finding.validation"]
      : config.mode === "bootstrap"
        ? ["finding.validation (not applicable: a bootstrap scan runs no validation stage)"]
        : []),
    ...(engineHooks === null ? ["finding.filtered"] : []),
    ...(runnerHooks === null
      ? ["model retries inside the harness runner", "token usage"]
      : ["token usage on the pi route"]),
    ...(engineHooks === null || untaggedCalls === 0
      ? []
      : [`context.selection for ${untaggedCalls} of ${modelCallIds.size} model invocations `
        + "(untagged: the threat planner reports no context, and not every specialist does)"]),
  ];

  const output = {
    schema_version: "2.0",
    driver_version: DRIVER_VERSION,
    harness: { root: config.harness_root, package_version: packageVersion, ...gitHead(config.harness_root) },
    // What this harness build exposed to be observed with, null for a build that exports
    // neither. Every capture claim the adapter makes about this run is read off these two.
    hooks: { runner: runnerHooks, engine: engineHooks },
    model: config.model,
    runner: config.runner,
    mode: config.mode,
    started_at: startedAt,
    finished_at: nowIso(),
    wall_ms: Date.now() - started,
    model_calls: modelCalls,
    model_call_failures: modelFailures,
    // CLI attempts, which is a different number from logical calls only where the runner
    // reports them; zero with no runner hooks, where an attempt is not observable at all.
    model_attempts: modelAttempts,
    observed_routes: [...observedRoutes].sort(),
    // Summed over the attempts that reported them. Null means nothing reported any, which is
    // not a measurement of zero: the pi route prints no usage and the mock runner calls nobody.
    usage_totals: usageObserved ? { ...usageTotals } : null,
    // The CLI's own estimate, summed and rounded to the microdollar so the record carries no
    // binary-float noise. It is an estimate the CLI reported, never a bill.
    cost_usd_cli_reported_total: costTotal === null ? null : Math.round(costTotal * 1e6) / 1e6,
    models_served: [...modelsServed].sort(),
    observer_records: observerRecords,
    // How many model invocations the engine reported context for, and how many it did not. An
    // untagged call is an uninstrumented one, never a call that was given no context.
    model_calls_with_context: [...modelCallIds].filter((id) => contextCallIds.has(id)).length,
    model_calls_without_context: untaggedCalls,
    // Context the engine reported for an invocation that never reached the runner (a budget
    // stop between the two). Zero is the normal reading.
    context_without_model_call: [...contextCallIds].filter((id) => !modelCallIds.has(id)).length,
    // The runner's count of this driver's own attempt hooks failing. Nonzero means attempt
    // observations were lost, so it is recorded next to the engine's equivalent rather than
    // being a silent hole in the attempt events.
    runner_hook_failures: typeof (baseRunner as { hookFailures?: unknown }).hookFailures === "number"
      ? (baseRunner as unknown as { hookFailures: number }).hookFailures
      : null,
    // "engine_records" when the submitted events carry the engine's candidate links, "summary"
    // when they are the older account read off the returned findings.
    finding_submitted_source: submittedSource,
    // The engine's own closing reading, when it reports one. It is taken after the summary was
    // built, so it can be higher than the summary's count; null means it was never reported.
    observer_scan_complete: scanComplete,
    observer_hook_failures: engineHooks === null
      ? null
      : (typeof record.observer?.hookFailures === "number" ? record.observer.hookFailures : null),
    progress_notes: progressNotes,
    summary,
    error: failure,
    trace: {
      mode: config.trace_mode,
      path: config.trace_mode === "off" ? null : config.trace_path ?? null,
      events_written: eventsWritten,
      state: observer.getState(),
      flush_timed_out: flushTimedOut,
      unavailable,
      tool_dispatch_note: "Tool dispatch happens inside the model CLI subprocess, which this driver spawns but "
        + "cannot see into. No tool event is emitted, and no absence of tool use is established.",
      usage_note: runnerHooks === null
        ? "This harness build exports no runner hooks, so no attempt, no token count and no cost estimate was observed."
        : "Token usage and the cost estimate are read from the claude CLI's own json result object. The pi route "
          + "prints no usage and the mock runner calls no model, so a run on either reports none; an absent count "
          + "is not a measurement of zero.",
      context_note: engineHooks === null
        ? "Context selection is read from the harness's own progress notes, which describe the scan rather than "
          + "report the prompt; nothing here is the engine's actual selection."
        : `The engine reported the context it supplied for ${modelCallIds.size - untaggedCalls} of `
          + `${modelCallIds.size} model invocations. The threat planner reports none and not every specialist `
          + "does, so a model.request with no context.selection is an uninstrumented call, not a call that was "
          + "given no context.",
    },
  };
  writeFileSync(config.output_path, JSON.stringify(output, null, 2));
  if (failure) process.exitCode = 1;
}

main().catch((error: unknown) => {
  const outputPath = (() => {
    try {
      const configPath = argValue("config");
      return configPath && existsSync(configPath) ? (JSON.parse(readFileSync(configPath, "utf8")) as DriverConfig).output_path : undefined;
    } catch {
      return undefined;
    }
  })();
  const message = error instanceof Error ? error.message : String(error);
  if (outputPath) {
    try {
      writeFileSync(outputPath, JSON.stringify({ schema_version: "2.0", driver_version: DRIVER_VERSION, summary: null,
        error: { name: "DriverFailure", message } }, null, 2));
    } catch {
      // Nothing else to record; the exit code carries the failure.
    }
  }
  console.error(message);
  process.exit(1);
});
