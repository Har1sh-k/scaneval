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

import {
  appendFileSync, chmodSync, closeSync, constants, copyFileSync, existsSync, fstatSync, lstatSync,
  mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, realpathSync, rmSync, writeFileSync,
  writeSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DRIVER_VERSION = "2.6.0";
// The route label of the image runtime's dedicated Pi runner. Deliberately not "pi": the old
// local route's declared tool policy is --no-tools, and this one is an explicit allowlist.
const PI_OCI_ROUTE = "pi-oci";

/** The image runtime's settings, written by the adapter; absent on the local runtime. */
interface ImageRuntimeConfig {
  pi_runner_entry: string;
  pi_extension: string;
  pi_synthetic_extension: string | null;
  exec_entry: string;
  pi_binary: string;
  pi_provider: string;
  pi_model_id: string;
  thinking_level: string;
  pi_auth_env: string | null;
  credential_valid_for_ms: number;
  runtime_receipt: string;
  research: { search: boolean; journal_dir: string; preflight_url: string | null };
  synthetic: { tool_calls: unknown[]; harness_mock: string } | null;
}

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
  pi_session_root?: string;
  run_id: string;
  producer_id: string;
  output_path: string;
  progress_path: string;
  flush_timeout_ms: number;
  runtime?: "local" | "oci_image";
  image?: ImageRuntimeConfig;
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

// Compatibility fingerprint for the harness's current outer planner retry helper. Its isolation
// wrapper gives every attempt a new argv array and temporary cwd, so identity and cwd cannot join
// the calls. The hash covers the stable request values instead, including the source-bearing
// prompt and environment, and is never written out. This is only correlation: the summary's
// native retry note is still required before a failed call is classified as recovered.
interface PlannerRetryIdentity {
  invocationId: string;
  requestFingerprint: string;
}

interface PendingPlannerTimeout {
  identity: PlannerRetryIdentity;
  runnerCallId: string;
}

interface ActivePlannerCall {
  identity: PlannerRetryIdentity;
  concurrent: boolean;
}

interface PlannerTimeoutRecovery {
  invocation_id: string;
  failed_runner_call_id: string;
  recovery_runner_call_id: string;
}

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

/**
 * Move one claude transcript into a call's private directory.
 *
 * The CLI writes `<config dir>/projects/<encoded cwd>/<session id>.jsonl`. The encoding of the
 * working directory is the CLI's business, so the projects directories are searched for the id
 * instead of rebuilding it. The id comes from the CLI's own result object and must look like one
 * before it is used in a path. Returns false when there was nothing to move.
 */
function moveClaudeTranscript(sessionId: string | null, destination: string): boolean {
  if (!sessionId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) return false;
  const projects = join(process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"), "projects");
  try {
    for (const entry of readdirSync(projects, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const source = join(projects, entry.name, `${sessionId}.jsonl`);
      if (!existsSync(source)) continue;
      mkdirSync(destination, { recursive: true, mode: 0o700 });
      copyFileSync(source, join(destination, `${sessionId}.jsonl`));
      rmSync(source);
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

interface InvocationView {
  model: string | null;
  thinking: string | null;
  promptChars: number;
  /** Kept inside the driver for source-map verification; emitted only through `content`. */
  prompt: string;
  route: string;
  content: Record<string, unknown>;
}

// securevibes-agent hands the runner pi-style argv with the prompt last; Fieldglass hands it a
// structured ModelRequest whose prompt travels on stdin. Describe either without changing it.
function describeInvocation(options: Record<string, unknown>, resolveBinary?: (args: string[]) => string): InvocationView {
  const args = Array.isArray(options.args) ? (options.args as string[]) : null;
  if (args) {
    const last = args.length > 0 ? args[args.length - 1] : "";
    const prompt = typeof last === "string" ? last : "";
    const flag = (name: string): string | null => {
      const index = args.indexOf(name);
      return index === -1 ? null : args[index + 1] ?? null;
    };
    return {
      model: flag("--model"),
      thinking: flag("--thinking"),
      promptChars: prompt.length,
      prompt,
      route: resolveBinary ? resolveBinary(args) : "unknown",
      content: { args },
    };
  }
  const request = (options.request ?? {}) as { route?: { driver?: string; model?: string }; effort?: string; prompt?: string };
  const route = request.route ?? {};
  const prompt = typeof request.prompt === "string" ? request.prompt : "";
  return {
    model: route.model ?? null,
    thinking: request.effort ?? null,
    promptChars: prompt.length,
    prompt,
    route: route.driver ?? "unknown",
    content: { request: { route: { driver: route.driver ?? null, model: route.model ?? null }, effort: request.effort ?? null, prompt: request.prompt ?? null } },
  };
}

function plannerRetryIdentity(options: PiInvocation, invocationId: unknown, stage: unknown): PlannerRetryIdentity | null {
  // The runner boundary is implemented by a pluggable JavaScript module, so its runtime value
  // can be thinner or stranger than the TypeScript interface promises. Correlation is optional
  // observation: malformed fields must make it unavailable, never make the runner call fail.
  try {
    if (stage !== "planner" || typeof invocationId !== "string" || !invocationId || !Array.isArray(options.args)
        || !options.args.every((arg) => typeof arg === "string")
        || typeof options.timeoutMs !== "number" || !Number.isFinite(options.timeoutMs)
        || !options.env || typeof options.env !== "object" || Array.isArray(options.env)) return null;
    const environment = Object.entries(options.env);
    if (!environment.every(([, value]) => typeof value === "string" || value === undefined)) return null;
    environment.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    // Snapshot array values before the call can mutate them. Sorted environment entries make
    // wrapper-created copies compare by value. Hashing avoids retaining or emitting API keys;
    // length-delimited JSON keeps boundaries unambiguous.
    const stableRequest = JSON.stringify([options.args.slice(), options.timeoutMs, environment]);
    return { invocationId, requestFingerprint: createHash("sha256").update(stableRequest).digest("hex") };
  } catch {
    return null;
  }
}

function samePlannerRetryIdentity(left: PlannerRetryIdentity, right: PlannerRetryIdentity): boolean {
  return left.invocationId === right.invocationId
    && left.requestFingerprint === right.requestFingerprint;
}

// Kept byte-for-byte equivalent to the current harness helper's timeout classifier. A different
// failure is never eligible for its timeout-only outer retry compatibility rule.
function isPlannerTimeoutMessage(message: string): boolean {
  return /(?:^|[^a-z0-9_])(?:llm_)?(?:time(?:d)?\s+out|timeout|timed_out)(?:$|[^a-z0-9_])/i.test(message);
}

function declaredPlannerTimeoutRetries(summary: unknown, mode: DriverConfig["mode"]): number {
  if (!summary || typeof summary !== "object") return 0;
  const planKey = mode === "bootstrap" ? "bootstrapPlan" : "changePlan";
  const plan = (summary as Record<string, unknown>)[planKey];
  if (!plan || typeof plan !== "object") return 0;
  const record = plan as Record<string, unknown>;
  // A successful retry leaves the LLM planner in charge. An exhausted one returns the heuristic
  // plan and is deliberately not a recovery declaration even though it carries the retry note.
  if (record.planner !== "llm" || !Array.isArray(record.notes)
      || !record.notes.includes("llm-planner-success")) return 0;
  return record.notes.filter((note) => note === "llm-planner-timeout-retry:1").length;
}

/** One runner invocation, linked to the harness's logical call and supplied context. */
interface CallState {
  callId: string;
  /** Unique runner invocation, even when an outer retry reuses the harness's logical ID. */
  runnerCallId: string;
  view: InvocationView;
  route: string;
  /** The `willRetry: false` record, stashed for the wrapper to pair with the returned result. */
  final: AttemptRecord | null;
  /** The session id each attempt's end record reported, in the order the attempts ended. */
  attemptSessions: Array<{ attempt: number; sessionId: string | null }>;
}

/**
 * One entry per native session a call can have left: per attempt on the claude route, where each
 * attempt reports its own session id, and per logical call on the pi route, where the CLI writes
 * into the call's own directory and reports no id. `transcript` says what became of it.
 */
interface SessionEntry {
  call: string;
  invocation_id: string;
  backend: "pi" | "claude";
  attempt: number | null;
  session_id: string | null;
  transcript: "moved" | "not_found" | "session_id_not_reported" | "in_call_directory";
}

const MAX_MAPPING_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_MAPPING_RETAINED_SOURCE_BYTES = 32 * 1024 * 1024;
const MAX_MAPPING_SOURCE_FILES = 256;
const MAX_MAPPING_RETAINED_PROMPT_CHARS = 32 * 1024 * 1024;
const MAX_MAPPING_RETAINED_PROMPT_RECORDS = 32768;
const MAX_BUFFERED_CONTEXT_RECORDS = 32768;
const MAX_MAPPING_LINE_CANDIDATES = 4096;
const MAX_PROMPT_OCCURRENCES = 4096;
const MAX_MAPPING_CANDIDATES_PER_RUN = 32768;
const MAX_MAPPING_HASH_CHARS_PER_RUN = 64 * 1024 * 1024;
const MAX_MAPPING_SEARCH_CHARS_PER_RUN = 128 * 1024 * 1024;
const HEX_SHA256 = /^[0-9a-f]{64}$/;

interface MappingBudget {
  candidates: number;
  hashChars: number;
  searchChars: number;
}

function spendMappingWork(budget: MappingBudget, kind: "candidate" | "hash" | "search",
                          amount: number): boolean {
  if (!Number.isSafeInteger(amount) || amount < 0) return false;
  if (kind === "candidate") {
    if (budget.candidates + amount > MAX_MAPPING_CANDIDATES_PER_RUN) return false;
    budget.candidates += amount;
  } else if (kind === "hash") {
    if (budget.hashChars + amount > MAX_MAPPING_HASH_CHARS_PER_RUN) return false;
    budget.hashChars += amount;
  } else {
    if (budget.searchChars + amount > MAX_MAPPING_SEARCH_CHARS_PER_RUN) return false;
    budget.searchChars += amount;
  }
  return true;
}

/** A regular UTF-8 file below the source-read bound, or null for every unsafe/unknown case. */
function readMappingSource(repoRoot: string, observedPath: unknown): string | null {
  if (typeof observedPath !== "string" || !observedPath || observedPath.startsWith("external:")) return null;
  // `isAbsolute` is platform-specific, so reject both POSIX and Windows spellings explicitly.
  if (isAbsolute(observedPath) || observedPath.startsWith("/") || observedPath.includes("\\")
      || /^[A-Za-z]:/.test(observedPath) || observedPath.includes("\0")) return null;
  const pieces = observedPath.split("/");
  if (pieces.some((piece) => !piece || piece === "." || piece === "..")) return null;

  let descriptor: number | null = null;
  try {
    const root = realpathSync(repoRoot);
    let candidate = root;
    for (let index = 0; index < pieces.length; index += 1) {
      candidate = join(candidate, pieces[index] as string);
      const status = lstatSync(candidate);
      // Even an in-repository symlink is refused: otherwise a later retarget could turn a
      // source verification into an external read between the path check and the open.
      if (status.isSymbolicLink()) return null;
      if (index < pieces.length - 1 && !status.isDirectory()) return null;
    }
    const status = lstatSync(candidate);
    if (!status.isFile() || status.size > MAX_MAPPING_SOURCE_BYTES) return null;
    const resolved = realpathSync(candidate);
    const beneath = relative(root, resolved);
    if (!beneath || beneath === ".." || beneath.startsWith(`..${sep}`) || isAbsolute(beneath)) return null;

    // O_NONBLOCK makes a raced-in FIFO harmless; O_NOFOLLOW refuses a final-component symlink
    // where the platform supports it. The identity checks make a changed path conservative;
    // this is defense in depth, not a claim that pathname APIs provide an atomic openat walk.
    descriptor = openSync(candidate, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.size > MAX_MAPPING_SOURCE_BYTES
        || opened.dev !== status.dev || opened.ino !== status.ino) return null;
    const rechecked = lstatSync(candidate);
    if (rechecked.isSymbolicLink() || !rechecked.isFile()
        || rechecked.dev !== opened.dev || rechecked.ino !== opened.ino
        || realpathSync(candidate) !== resolved) return null;

    // Read at most the opened size plus one byte. A file appended after fstat is rejected after
    // that sentinel byte instead of letting readFileSync grow without a bound.
    const bytes = Buffer.allocUnsafe(opened.size + 1);
    let read = 0;
    while (read < bytes.length) {
      const count = readSync(descriptor, bytes, read, bytes.length - read, null);
      if (count === 0) break;
      read += count;
    }
    const afterRead = fstatSync(descriptor);
    if (read !== opened.size || afterRead.size !== opened.size
        || afterRead.dev !== opened.dev || afterRead.ino !== opened.ino) return null;
    const payload = bytes.subarray(0, read);
    const text = payload.toString("utf8");
    // Buffer's UTF-8 decoder substitutes malformed input. A substituted string is not the
    // source bytes whose hash the harness saw, so reject it rather than verifying a different file.
    if (!Buffer.from(text, "utf8").equals(payload)) return null;
    return text;
  } catch {
    return null;
  } finally {
    if (descriptor !== null) {
      try { closeSync(descriptor); } catch { /* The mapping simply remains unverified. */ }
    }
  }
}

function sha256Text(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Locate two 1-based source lines in one bounded pass without allocating an index per line. */
function lineWindows(text: string, start: number, end: number): {
  startFirst: number; startAfter: number; endFirst: number; endAfter: number;
} | null {
  let line = 1;
  let startFirst: number | null = start === 1 ? 0 : null;
  let startAfter: number | null = null;
  let endFirst: number | null = end === 1 ? 0 : null;
  let endAfter: number | null = null;
  for (let newline = text.indexOf("\n"); newline !== -1;
       newline = text.indexOf("\n", newline + 1)) {
    const next = newline + 1;
    if (line === start) startAfter = next;
    if (line === end) endAfter = next;
    line += 1;
    if (line === start) startFirst = next;
    if (line === end) endFirst = next;
    if (startAfter !== null && endAfter !== null) break;
  }
  if (startFirst === null || endFirst === null) return null;
  return {
    startFirst,
    startAfter: startAfter ?? text.length,
    endFirst,
    endAfter: endAfter ?? text.length,
  };
}

/** Whether `candidate` plus its declared synthetic suffix occurs with the reported digest. */
function promptCarriesMarkedSpan(prompt: string, candidate: string, chars: number, digest: string,
                                 budget: MappingBudget): boolean {
  if (!spendMappingWork(budget, "search", prompt.length)) return false;
  let occurrences = 0;
  for (let offset = prompt.indexOf(candidate); offset !== -1;
       offset = prompt.indexOf(candidate, offset + 1)) {
    occurrences += 1;
    if (occurrences > MAX_PROMPT_OCCURRENCES) return false;
    const fragment = prompt.slice(offset, offset + chars);
    if (!spendMappingWork(budget, "hash", fragment.length)) return false;
    if (fragment.length === chars && fragment.slice(0, candidate.length) === candidate
        && sha256Text(fragment) === digest) return true;
  }
  return false;
}

/**
 * Prove an old v1 `truncated` range is one exact contiguous source slice.
 *
 * The old shape used the same flag for prefixes and rendered declarations. Its hash identifies
 * prompt text, not a source map. Verification therefore needs all three facts: one unique source
 * occurrence, derived start/end lines equal to the reported boundaries, and the same fragment in
 * the actual correlated prompt. Work is bounded to one source line's possible starts.
 */
function verifiesExactTruncatedMapping(span: Record<string, unknown>, prompt: string,
                                       source: string | null, budget: MappingBudget): boolean {
  if (source === null) return false;
  const start = span.startLine;
  const end = span.endLine;
  const chars = span.chars;
  const digest = span.sha256;
  const marker = span.markerChars === undefined ? 0 : span.markerChars;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || !Number.isSafeInteger(chars)
      || !Number.isSafeInteger(marker) || typeof digest !== "string" || !HEX_SHA256.test(digest)
      || (start as number) < 1 || (end as number) < (start as number)
      || (chars as number) < 1 || (marker as number) < 0 || (marker as number) >= (chars as number)) {
    return false;
  }
  const sourceChars = (chars as number) - (marker as number);
  // Account for the one source pass before doing or allocating work based on its contents.
  if (!spendMappingWork(budget, "search", source.length)) return false;
  const windows = lineWindows(source, start as number, end as number);
  if (windows === null
      || windows.startAfter - windows.startFirst > MAX_MAPPING_LINE_CANDIDATES) return false;

  let verified = 0;
  for (let offset = windows.startFirst; offset < windows.startAfter; offset += 1) {
    if (!spendMappingWork(budget, "candidate", 1)) return false;
    const after = offset + sourceChars;
    if (after > source.length || after <= windows.endFirst || after > windows.endAfter) continue;
    const candidate = source.slice(offset, after);
    let promptMatch = false;
    if ((marker as number) === 0) {
      // Hash first: only the matching candidate pays for whole-source uniqueness searches.
      if (!spendMappingWork(budget, "hash", candidate.length)) return false;
      if (sha256Text(candidate) !== digest) continue;
      if (!spendMappingWork(budget, "search", source.length * 2 + prompt.length)) return false;
      promptMatch = prompt.includes(candidate);
    } else {
      promptMatch = promptCarriesMarkedSpan(prompt, candidate, chars as number, digest, budget);
      if (!promptMatch) continue;
      if (!spendMappingWork(budget, "search", source.length * 2)) return false;
    }
    // A hash cannot select between identical source occurrences. The reported envelope is not
    // used to break the tie, because that is the mapping under examination.
    if (source.indexOf(candidate) !== offset || source.indexOf(candidate, offset + 1) !== -1) continue;
    if (!promptMatch) continue;
    verified += 1;
    if (verified > 1) return false;
  }
  return verified === 1;
}

function suppliedSpan(span: Record<string, unknown>, prompt: string | null,
                      sourceFor: (path: unknown) => string | null,
                      budget: MappingBudget): Record<string, unknown> {
  const truncated = typeof span.truncated === "boolean" ? span.truncated : null;
  let locationKnown = span.locationKnown === undefined || span.locationKnown === true;
  let mappingVerified = false;
  if (locationKnown && truncated === true) {
    mappingVerified = prompt !== null
      && verifiesExactTruncatedMapping(span, prompt, sourceFor(span.path), budget);
    locationKnown = mappingVerified;
  } else if (locationKnown && truncated !== false) {
    // A malformed v1 record cannot be silently converted into the untruncated case.
    locationKnown = false;
  }
  return {
    path: String(span.path ?? ""),
    start_line: wireNumber(span.startLine),
    end_line: wireNumber(span.endLine),
    chars: wireNumber(span.chars),
    sha256: String(span.sha256 ?? ""),
    truncated,
    original_chars: wireNumber(span.originalChars),
    // How many of `chars` are a synthetic truncation marker rather than supplied source, when
    // the engine says. Null means it did not, not that there was no marker.
    marker_chars: wireNumber(span.markerChars),
    role: String(span.role ?? "other"),
    // Absent on the record means the line numbers are real file positions; false means the
    // supplied text could not be located and the lines are 1..N of that text instead. A
    // consumer joining spans against source locations must not treat those as file positions,
    // so the flag is always present here rather than only when it is false.
    location_known: locationKnown,
    ...(mappingVerified ? { source_mapping: "verified_exact" } : {}),
  };
}

// What a non-span input to a prompt may be called. A planner is given a file inventory, a change
// summary or an architecture description rather than located source, and those are described
// rather than dressed up as spans. A kind outside this list is reported as "other", so the
// vocabulary stays closed whatever a harness passes.
const INPUT_KINDS = new Set([
  "file_inventory", "change_summary", "diff", "architecture_context", "threat_model",
  "prior_findings", "instructions", "other",
]);

function suppliedInput(input: Record<string, unknown>): Record<string, unknown> {
  const kind = typeof input.kind === "string" && INPUT_KINDS.has(input.kind) ? input.kind : "other";
  const digest = typeof input.sha256 === "string" && /^[0-9a-f]{64}$/.test(input.sha256) ? input.sha256 : null;
  return {
    kind,
    chars: wireNumber(input.chars),
    sha256: digest,
    // How many entries the input lists, when it is a list (files in an inventory, say).
    items: wireNumber(input.items),
    // Null when the harness did not say, which is not a claim that nothing was cut.
    truncated: typeof input.truncated === "boolean" ? input.truncated : null,
    original_chars: wireNumber(input.originalChars),
    omitted_items: wireNumber(input.omittedItems),
  };
}

/** Copy exactly the hook fields this driver reads before returning to mutable caller code. */
function snapshotContextRecord(record: Record<string, unknown>): {
  record: Record<string, unknown> | null; callId: string | null;
} {
  let invocationId: unknown;
  try {
    invocationId = record.invocationId;
  } catch {
    return { record: null, callId: null };
  }
  const callId = typeof invocationId === "string" ? invocationId : null;
  try {
    const spansValue = record.spans;
    const inputsValue = record.inputs;
    const omittedPathsValue = record.omittedPaths;
    const spans = Array.isArray(spansValue)
      ? spansValue.map((span) => typeof span === "object" && span !== null ? { ...span } : span)
      : spansValue;
    const inputs = Array.isArray(inputsValue)
      ? inputsValue.map((input) => typeof input === "object" && input !== null ? { ...input } : input)
      : inputsValue;
    return {
      callId,
      record: {
        invocationId,
        stage: record.stage,
        promptChars: record.promptChars,
        spans,
        inputs,
        truncatedSpans: record.truncatedSpans,
        omittedPaths: Array.isArray(omittedPathsValue) ? [...omittedPathsValue] : omittedPathsValue,
        hypothesisId: record.hypothesisId,
        specialistId: record.specialistId,
      },
    };
  } catch {
    return { record: null, callId };
  }
}

// ---- image runtime (config.runtime = "oci_image") ----------------------------------------------

const MAX_CREDENTIAL_CHARS = 64 * 1024;
const REFRESH_DISABLED = "scaneval-refresh-disabled";
const MAX_RECEIPT_BYTES = 64 * 1024;
// What a Pi process of the image route inherits from this driver's environment, by name. Nothing
// else is passed: no provider API key, no credential variable, no operator setting.
const PI_ENV_PASSTHROUGH = ["PATH", "LANG", "LC_ALL", "TERM", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY",
  "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SCANEVAL_RETRIEVAL_URL"];

interface ImageRuntimeState {
  image: ImageRuntimeConfig;
  agentDir: string;
  environment: Record<string, string>;
  credential: { env: string | null; provider: string; materialized: boolean; removed: boolean | null };
  receipt: Record<string, unknown> | null;
  receiptError: string | null;
  piVersion: string | null;
  piVersionError: string | null;
  files: Record<string, { path: string; sha256: string | null }>;
}

/**
 * Check the single-provider OAuth credential and return the auth.json text Pi will read.
 *
 * Every message names the variable and what was wrong with its shape, never a value: an error
 * here travels into the driver output and the adapter's record.
 */
function piAuthDocument(raw: string | undefined, provider: string, name: string, validForMs: number,
                        now = Date.now()): string {
  if (raw === undefined || raw === "") {
    throw new Error(`the Pi credential variable ${name} is not set in the scanner container: declare it under `
      + `execution.credentials with provider ${provider}, and export in it a JSON object holding exactly one `
      + `"${provider}" OAuth entry`);
  }
  if (raw.length > MAX_CREDENTIAL_CHARS) throw new Error(`the Pi credential variable ${name} is larger than ${MAX_CREDENTIAL_CHARS} characters`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`the Pi credential variable ${name} is not JSON; it must hold {"${provider}": {"type": "oauth", ...}}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`the Pi credential variable ${name} is not a JSON object`);
  }
  const keys = Object.keys(parsed);
  if (keys.length !== 1 || keys[0] !== provider) {
    throw new Error(`the Pi credential variable ${name} must hold exactly one entry, for provider ${provider}; `
      + `it holds ${keys.length} entr${keys.length === 1 ? "y" : "ies"}${keys.length === 1 ? " for another provider" : ""}`);
  }
  const entry = (parsed as Record<string, unknown>)[provider] as Record<string, unknown> | null;
  if (!entry || typeof entry !== "object" || Array.isArray(entry) || entry.type !== "oauth") {
    throw new Error(`the ${provider} entry in ${name} must be an OAuth credential (type "oauth"); this route accepts `
      + "no API key and falls back to no paid provider");
  }
  if (Object.hasOwn(entry, "refresh")) {
    throw new Error(`the ${provider} OAuth entry in ${name} must be access-only: omit the refresh field; `
      + "a refresh token must never enter a scanner container");
  }
  if (Object.keys(entry).some((key) => !["type", "access", "expires", "accountId"].includes(key))) {
    throw new Error(`the ${provider} OAuth entry in ${name} contains unsupported fields; `
      + "export only type, access, expires, and optional accountId");
  }
  if (Object.hasOwn(entry, "accountId") && (typeof entry.accountId !== "string" || !entry.accountId)) {
    throw new Error(`the ${provider} OAuth entry in ${name} has an invalid accountId`);
  }
  if (typeof entry.access !== "string" || !entry.access) {
    throw new Error(`the ${provider} OAuth entry in ${name} has no access token`);
  }
  if (typeof entry.expires !== "number" || !Number.isFinite(entry.expires) || Math.abs(entry.expires) >= 2 ** 53) {
    throw new Error(`the ${provider} OAuth entry in ${name} has no numeric expiry`);
  }
  if (!Number.isFinite(validForMs) || validForMs < 360_000 || validForMs >= 2 ** 53) {
    throw new Error("the Pi access-token validity window must be finite and include its refresh margin");
  }
  if (entry.expires <= now + validForMs) {
    throw new Error(`the ${provider} access token in ${name} has expired or expires within ${Math.round(validForMs / 1000)} seconds, `
      + "before this scan's limit and Pi's refresh window; refresh it explicitly once (pi auth check) before the run, "
      + "nothing inside the scan refreshes it");
  }
  // Only the fields Pi needs to use the access token. The refresh token is never written: Pi
  // cannot refresh inside the scan, so no copy of the operator's credential is ever rotated by
  // one shard underneath another. A refresh Pi attempts anyway fails, visibly, with this value.
  return JSON.stringify({ [provider]: {
    type: "oauth", access: entry.access, refresh: REFRESH_DISABLED, expires: entry.expires,
    ...(typeof entry.accountId === "string" ? { accountId: entry.accountId } : {}),
  } });
}

function fileDigest(path: string): string | null {
  try {
    return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
  } catch {
    return null;
  }
}

function readReceipt(path: string): { receipt: Record<string, unknown> | null; error: string | null } {
  try {
    const descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      const status = fstatSync(descriptor);
      if (!status.isFile() || status.size > MAX_RECEIPT_BYTES) return { receipt: null, error: "the runtime receipt is not a bounded regular file" };
      const parsed = JSON.parse(readFileSync(descriptor, "utf8"));
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? { receipt: parsed as Record<string, unknown>, error: null }
        : { receipt: null, error: "the runtime receipt is not a JSON object" };
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    return { receipt: null, error: `the runtime receipt could not be read (${error instanceof Error ? error.name : "error"})` };
  }
}

/**
 * Everything the image route needs before the engine starts: the credential in a private agent
 * directory, the Pi environment, and the identities of what is about to run.
 *
 * The credential variable is removed from this process's environment first, whatever happens
 * next, so no child this driver or the harness starts (git, pi, anything) can inherit it.
 */
function prepareImageRuntime(config: DriverConfig): ImageRuntimeState {
  const image = config.image;
  if (!image || typeof image !== "object") throw new Error("the image runtime was selected without its settings");
  const rawCredential = image.pi_auth_env ? process.env[image.pi_auth_env] : undefined;
  if (image.pi_auth_env) delete process.env[image.pi_auth_env];
  if (image.synthetic && rawCredential !== undefined) {
    throw new Error("the synthetic diagnostic route takes no credential, and one was passed");
  }
  const authText = image.synthetic ? null : piAuthDocument(rawCredential, image.pi_provider, image.pi_auth_env ?? "(none)",
    image.credential_valid_for_ms);
  if (!process.env.SCANEVAL_RETRIEVAL_URL) {
    throw new Error("the open-context research route needs SCANEVAL_RETRIEVAL_URL, which the oci backend sets "
      + "only under the public_research network policy; it was not set, so nothing was run");
  }
  const agentDir = mkdtempSync(join(tmpdir(), "scaneval-pi-agent-"));
  chmodSync(agentDir, 0o700);
  process.on("exit", () => {
    try { rmSync(agentDir, { recursive: true, force: true }); } catch { /* recorded as not removed */ }
  });
  if (authText !== null) {
    const descriptor = openSync(join(agentDir, "auth.json"), "wx", 0o600);
    try {
      writeSync(descriptor, authText);
    } finally {
      closeSync(descriptor);
    }
    chmodSync(join(agentDir, "auth.json"), 0o600);
  }
  mkdirSync(image.research.journal_dir, { recursive: true, mode: 0o755 });
  const environment: Record<string, string> = {};
  for (const name of PI_ENV_PASSTHROUGH) {
    const value = process.env[name];
    if (typeof value === "string" && !value.includes("\0")) environment[name] = value;
  }
  Object.assign(environment, {
    HOME: tmpdir(), TMPDIR: tmpdir(), PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", PI_TELEMETRY: "0",
    SCANEVAL_OPEN_CONTEXT_REPO: config.repo_path,
    SCANEVAL_OPEN_CONTEXT_SEARCH: image.research.search ? "1" : "0",
    SCANEVAL_OPEN_CONTEXT_JOURNAL: image.research.journal_dir,
    ...(image.synthetic ? {
      SCANEVAL_SYNTHETIC_TOOL_CALLS: JSON.stringify(image.synthetic.tool_calls),
      SCANEVAL_SYNTHETIC_HARNESS_MOCK: image.synthetic.harness_mock,
    } : {}),
  });
  const { receipt, error: receiptError } = readReceipt(image.runtime_receipt);
  let piVersion: string | null = null;
  let piVersionError: string | null = null;
  try {
    piVersion = execFileSync(image.pi_binary, ["--version"], { env: { ...environment, PI_CODING_AGENT_DIR: agentDir },
      encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] }).trim().slice(0, 200) || null;
  } catch (error) {
    piVersionError = `pi --version failed (${error instanceof Error ? error.name : "error"})`;
  }
  const toolsHelper = join(dirname(image.pi_extension), "pi_open_context_tools.mjs");
  const files: ImageRuntimeState["files"] = {};
  for (const [role, path] of [["driver", fileURLToPath(import.meta.url)], ["runner", image.pi_runner_entry],
    ["extension", image.pi_extension], ["extension_tools", toolsHelper],
    ...(image.pi_synthetic_extension ? [["synthetic_provider", image.pi_synthetic_extension]] : [])] as Array<[string, string]>) {
    files[role] = { path, sha256: fileDigest(path) };
  }
  return { image, agentDir, environment,
    credential: { env: image.pi_auth_env, provider: image.pi_provider, materialized: authText !== null, removed: null },
    receipt, receiptError, piVersion, piVersionError, files };
}

/** The exact tool allowlist the image route declares to the model; nothing built in. */
function imageTools(image: ImageRuntimeConfig): string[] {
  return ["scaneval_fetch", ...(image.research.search ? ["scaneval_search"] : []), "scaneval_git", "scaneval_read"];
}

/** One bounded public fetch through the recorded API, identified as a preflight, never as research. */
async function researchPreflight(state: ImageRuntimeState): Promise<Record<string, unknown> | null> {
  const url = state.image.research.preflight_url;
  if (!url) return null;
  try {
    const tools = await import(pathToFileURL(join(dirname(state.image.pi_extension), "pi_open_context_tools.mjs")).href);
    const { reply } = await tools.postRetrieval(new URL(String(process.env.SCANEVAL_RETRIEVAL_URL)), "/fetch",
      { url, source: "scanner_native" });
    const chain = Array.isArray(reply?.redirect_chain) ? reply.redirect_chain : [];
    return { purpose: "transport preflight by the driver, before any model call; not model research", url,
      outcome: reply?.outcome ?? null, http_status: chain.length ? chain[chain.length - 1]?.status ?? null : null,
      content_sha256: reply?.content_sha256 ?? null, retrieval_event_id: reply?.id ?? null };
  } catch (error) {
    return { purpose: "transport preflight by the driver, before any model call; not model research", url,
      outcome: "client_error", error: error instanceof Error ? error.message.slice(0, 200) : "error" };
  }
}

async function main(): Promise<void> {
  const configPath = argValue("config");
  if (!configPath) throw new Error("--config <path> is required");
  const config = JSON.parse(readFileSync(configPath, "utf8")) as DriverConfig;
  const startedAt = nowIso();
  const started = Date.now();
  // First, before any module of the harness is loaded: the credential leaves the environment.
  const imageState = config.runtime === "oci_image" ? prepareImageRuntime(config) : null;

  const engineModule = await import(pathToFileURL(join(config.harness_root, config.engine_entry)).href);
  const runnerModule = await import(pathToFileURL(join(config.harness_root, config.runner_entry)).href);
  const observerModule = await import(pathToFileURL(config.observer_sdk).href);

  // Capability detection, once, by what the harness build actually exports. Every branch below
  // reads these two and nothing else, so an older harness takes the pre-hooks path in all of
  // them rather than in the ones somebody remembered. The image route composes its own raw
  // runner under the harness's retry and isolation wrappers and passes them no hooks, so it is
  // observed per logical call whatever the build exports, and its route is named explicitly
  // rather than resolved off argv by a helper the pinned build does not export.
  const runnerHooks: number | null = imageState ? null : runnerModule.PI_RUNNER_HOOKS_VERSION ?? null;
  const engineHooks: number | null = engineModule.HARNESS_OBSERVER_VERSION ?? null;
  const resolveBinary: ((args: string[]) => string) | undefined = imageState
    ? () => PI_OCI_ROUTE : runnerModule.resolveRunnerBinary;

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
  // A failed runner invocation is never erased. These two collections only establish whether
  // the harness's timeout-only planner helper later recovered that particular failure.
  const pendingPlannerTimeouts: PendingPlannerTimeout[] = [];
  const activePlannerCalls: ActivePlannerCall[] = [];
  const ambiguousPlannerRetryIdentities: PlannerRetryIdentity[] = [];
  const plannerRecoveryCandidates: PlannerTimeoutRecovery[] = [];
  let plannerTimeoutFailures = 0;
  let modelAttempts = 0;
  let piSessionCalls = 0;
  const piSessionCallIds: string[] = [];
  let claudeSessionCalls = 0;
  const claudeSessionCallIds: string[] = [];
  // Calls with at least one attempt whose transcript was not moved, for readers of the older field.
  const claudeSessionMissing: string[] = [];
  // Every native session a captured call can have left, by call, backend and attempt. The
  // adapter reconciles it with what it registers and builds its history notes from it alone.
  const sessionManifest: SessionEntry[] = [];

  /**
   * Move every transcript a claude call's attempts left, failed and retried attempts included.
   * The ids come from each attempt's end record when the runner reports attempts, and from the
   * returned result otherwise; a call that threw before returning still has its attempts.
   */
  function archiveClaudeSessions(state: CallState, minted: string, result: PiResult | null, destination: string): void {
    const reported = [...state.attemptSessions];
    const returned = result?.structured?.sessionId ?? null;
    if (returned && !reported.some((entry) => entry.sessionId === returned)) {
      reported.push({ attempt: state.final?.attempt ?? (reported.length ? reported[reported.length - 1].attempt : 1), sessionId: returned });
    }
    if (reported.length === 0) reported.push({ attempt: 1, sessionId: null });
    const moved = new Set<string>();
    let complete = true;
    for (const { attempt, sessionId } of reported) {
      let transcript: SessionEntry["transcript"] = "session_id_not_reported";
      if (sessionId) {
        transcript = moved.has(sessionId) || moveClaudeTranscript(sessionId, destination) ? "moved" : "not_found";
        if (transcript === "moved") moved.add(sessionId);
      }
      if (transcript !== "moved") complete = false;
      sessionManifest.push({ call: minted, invocation_id: state.callId, backend: "claude",
        attempt: runnerHooks === null ? null : attempt, session_id: sessionId, transcript });
    }
    if (!complete) claudeSessionMissing.push(minted);
  }
  // Which CLI actually served each call. The tool policy differs by route, and neither
  // route's tool dispatch happens in this process, so this records what was asked for,
  // never what the CLI did with it.
  const observedRoutes = new Set<string>();
  // Runner hooks use this driver's unique ID internally. The emitted call_id stays the
  // harness's logical ID so context and finding events retain their original association.
  const calls = new Map<string, CallState>();
  // Which invocations were seen from each side. Not every model call is instrumented -- the
  // Some harness stages do not report supplied spans, so count coverage rather than guessing
  // which stage caused each gap.
  const modelCallIds = new Set<string>();
  const contextCallIds = new Set<string>();
  const mappingSourceCache = new Map<string, string | null>();
  const mappingBudget: MappingBudget = { candidates: 0, hashChars: 0, searchChars: 0 };
  let mappingSourceBytes = 0;
  let mappingPromptChars = 0;
  let mappingPromptRecords = 0;
  let contextLifecycleOrder = 0;
  let contextSnapshotFailures = 0;
  let contextBufferExhausted = false;
  type BufferedContext = {
    record: Record<string, unknown>; order: number; sourceTimestamp: string; beforeFirstCall: boolean;
  };
  const bufferedContext: BufferedContext[] = [];
  const contextsByCallId = new Map<string, BufferedContext[]>();
  const promptsByCallId = new Map<string, Array<{ prompt: string; order: number }>>();
  const promptRetentionFailed = new Set<string>();

  function snapshotSource(path: unknown): string | null {
    if (typeof path !== "string") return null;
    if (!mappingSourceCache.has(path)) {
      if (mappingSourceCache.size >= MAX_MAPPING_SOURCE_FILES) return null;
      const source = readMappingSource(config.repo_path, path);
      const bytes = source === null ? 0 : Buffer.byteLength(source, "utf8");
      if (source !== null && mappingSourceBytes + bytes > MAX_MAPPING_RETAINED_SOURCE_BYTES) {
        mappingSourceCache.set(path, null);
      } else {
        mappingSourceCache.set(path, source);
        mappingSourceBytes += bytes;
      }
    }
    return mappingSourceCache.get(path) ?? null;
  }

  function cachedSource(path: unknown): string | null {
    return typeof path === "string" ? mappingSourceCache.get(path) ?? null : null;
  }

  /** Snapshot only source a potentially exact old truncated span could need, at call time. */
  function snapshotContextSources(record: Record<string, unknown>): void {
    if (config.trace_mode === "off") return;
    if (!Array.isArray(record.spans)) return;
    for (const raw of record.spans) {
      if (typeof raw !== "object" || raw === null) continue;
      const span = raw as Record<string, unknown>;
      const located = span.locationKnown === undefined || span.locationKnown === true;
      if (located && span.truncated === true) snapshotSource(span.path);
    }
  }

  /** Emit one engine context record once its actual runner prompt is available. */
  async function emitContextRecord(record: Record<string, unknown>, prompt: string | null,
                                   sourceTimestamp: string): Promise<void> {
    const spans = (Array.isArray(record.spans) ? record.spans : [])
      .map((span) => typeof span === "object" && span !== null
        ? span as Record<string, unknown> : {});
    const inputs = (Array.isArray(record.inputs) ? record.inputs : [])
      .filter((input): input is Record<string, unknown> => typeof input === "object" && input !== null);
    await observer.emit({
      type: "context.selection",
      // The engine reports the whole set it supplied for this invocation, which is the one
      // thing a derived self-report cannot claim. Mapping verification can make an individual
      // old span unlocated; it does not make the event incomplete.
      capture_status: "complete",
      ...(typeof record.invocationId === "string" ? { call_id: record.invocationId } : {}),
      metadata: {
        source: "harness_emitted",
        // Mapping verification is deferred until the logical call's lifecycle is known. Keep
        // the callback time separate from the emitter's later event timestamp.
        source_timestamp: sourceTimestamp,
        source_timestamp_of: "harness_context_callback",
        stage: record.stage ?? null,
        prompt_chars: wireNumber(record.promptChars),
        span_count: spans.length,
        spans: spans.map((span) => suppliedSpan(span, prompt, cachedSource, mappingBudget)),
        // The inputs that are not located source: an inventory, a change summary, an
        // architecture description. A record with inputs and no spans is a prompt built
        // from those, not a prompt given nothing.
        input_count: inputs.length,
        inputs: inputs.map(suppliedInput),
        truncated_spans: wireNumber(record.truncatedSpans),
        omitted_paths: Array.isArray(record.omittedPaths) ? record.omittedPaths : [],
        hypothesis_id: record.hypothesisId ?? null,
        specialist_id: record.specialistId ?? null,
      },
    });
  }

  // Count runner invocations, not distinct logical IDs: a planner may call its runner again
  // after exhausting the runner's inner retries and reuse the same context and logical ID.
  const runnerCalls: Array<{ callId: string; stage: string }> = [];
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

  function attemptId(state: CallState, attempt: number): string {
    return `${state.callId}/${state.runnerCallId}/attempt-${attempt}`;
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
        ...(state ? { call_id: state.callId, attempt_id: attemptId(state, record.attempt) } : {}),
        metadata: {
          source: "harness_runner_hook",
          runner_call_id: state?.runnerCallId ?? null,
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
      state?.attemptSessions.push({ attempt: record.attempt, sessionId: record.structured?.sessionId ?? null });
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
        ...(state ? { call_id: state.callId, attempt_id: attemptId(state, record.attempt) } : {}),
        duration_ms: Math.max(0, Math.round(record.durationMs)),
        metadata: {
          source: "harness_runner_hook",
          runner_call_id: state?.runnerCallId ?? null,
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

  // What the image route's Pi processes reported about themselves, aggregated over every call.
  // Pi's message metadata names the provider and model Pi addressed; that is the client's own
  // routing record, never a provider's statement of the model it served.
  const piCallSummary = {
    calls: 0, nonzero_exits: 0, unparsed_stream_records: 0, thinking_overridden: 0, session_dirs_used: 0,
    stop_reasons: {} as Record<string, number>, providers_addressed: {} as Record<string, number>,
    models_addressed: {} as Record<string, number>, replaced_stage_flags: {} as Record<string, number>,
    tool_executions: {} as Record<string, { ok: number; error: number }>,
  };
  const bump = (table: Record<string, number>, key: string | null) => {
    const name = key ?? "unknown";
    table[name] = (table[name] ?? 0) + 1;
  };
  function observePiCall(observation: Record<string, unknown>): void {
    piCallSummary.calls += 1;
    if (observation.exit_code !== 0) piCallSummary.nonzero_exits += 1;
    piCallSummary.unparsed_stream_records += Number(observation.stream_unparsed_records) || 0;
    if (observation.thinking_requested_by_stage !== null
        && observation.thinking_requested_by_stage !== observation.thinking_applied) piCallSummary.thinking_overridden += 1;
    if (observation.session_dir_used === true) piCallSummary.session_dirs_used += 1;
    bump(piCallSummary.stop_reasons, typeof observation.stop_reason === "string" ? observation.stop_reason : null);
    bump(piCallSummary.providers_addressed, typeof observation.provider_addressed === "string" ? observation.provider_addressed : null);
    bump(piCallSummary.models_addressed, typeof observation.model_addressed === "string" ? observation.model_addressed : null);
    for (const flag of Array.isArray(observation.replaced_stage_flags) ? observation.replaced_stage_flags : []) {
      bump(piCallSummary.replaced_stage_flags, String(flag));
    }
    for (const execution of Array.isArray(observation.tool_executions) ? observation.tool_executions : []) {
      const name = typeof execution?.name === "string" ? execution.name : "unknown";
      const entry = piCallSummary.tool_executions[name] ?? { ok: 0, error: 0 };
      if (execution?.is_error === true) entry.error += 1;
      else entry.ok += 1;
      piCallSummary.tool_executions[name] = entry;
    }
    const usage = observation.usage as Record<string, number> | null;
    if (usage && typeof usage === "object") {
      for (const [from, to] of [["input", "input_tokens"], ["output", "output_tokens"], ["cacheRead", "cache_read_input_tokens"],
        ["cacheWrite", "cache_creation_input_tokens"]] as const) {
        const value = wireNumber(usage[from]);
        if (value === null) continue;
        usageTotals[to] = (usageTotals[to] ?? 0) + value;
        usageObserved = true;
      }
      const cost = usage.cost;
      if (typeof cost === "number" && Number.isFinite(cost) && cost > 0) costTotal = (costTotal ?? 0) + cost;
    }
  }

  async function imageRunner(state: ImageRuntimeState): Promise<PiRunner> {
    const ociModule = await import(pathToFileURL(state.image.pi_runner_entry).href);
    const execModule = await import(pathToFileURL(join(config.harness_root, state.image.exec_entry)).href);
    const raw = ociModule.createPiOciRawRunner({
      exec: execModule.execCommand,
      piBinary: state.image.pi_binary,
      provider: state.image.pi_provider,
      modelId: state.image.pi_model_id,
      requestedModel: config.model,
      thinkingLevel: state.image.thinking_level,
      agentDir: state.agentDir,
      extensions: [state.image.pi_extension, ...(state.image.pi_synthetic_extension ? [state.image.pi_synthetic_extension] : [])],
      tools: imageTools(state.image),
      environment: state.environment,
      sessionRoot: config.pi_session_root ?? null,
      onCall: observePiCall,
    });
    // Composed exactly as upstream's createDefaultPiRunner composes its own exec.
    return runnerModule.createRetryingPiRunner(runnerModule.createIsolatedPiRunner(raw)) as PiRunner;
  }

  const baseRunner: PiRunner = imageState ? await imageRunner(imageState) : config.runner === "mock"
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
        metadata: { source: "driver_runner_wrapper", runner_call_id: state.runnerCallId,
                    model_requested: state.view.model,
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
        runner_call_id: state.runnerCallId,
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
      ...(record ? { attempt_id: attemptId(state, record.attempt) } : {}),
      // The attempt's own duration, as the runner measured it, so every attempt event in a
      // run is the same measurement. The wrapper's elapsed time spans the earlier attempts and
      // the backoffs between them, which is a different quantity and is recorded as one.
      duration_ms: record ? Math.max(0, Math.round(record.durationMs)) : elapsed,
      metadata: {
        source: "harness_runner_hook",
        runner_call_id: state.runnerCallId,
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
      // Only an evaluated pi call changes its session policy. Each logical call gets a
      // separate directory, so removing --no-session preserves history without carrying
      // model context from one hypothesis into the next. Ordinary harness runs are untouched.
      const binary = config.runner === "mock" ? "mock"
        : options.args && resolveBinary ? resolveBinary(options.args) : "unknown";
      let observedOptions = options;
      if ((binary === "pi" || binary === PI_OCI_ROUTE) && config.pi_session_root && options.args) {
        const sessionDir = join(config.pi_session_root, minted);
        mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
        observedOptions = {
          ...options,
          args: options.args.filter((arg) => arg !== "--no-session"),
          env: { ...options.env, PI_CODING_AGENT_SESSION_DIR: sessionDir },
        };
        piSessionCalls += 1;
        piSessionCallIds.push(minted);
        sessionManifest.push({ call: minted, invocation_id: meta.invocationId ?? minted, backend: "pi",
          attempt: null, session_id: null, transcript: "in_call_directory" });
      }
      // The claude route has no session-directory variable, so the CLI keeps its transcript
      // under its own projects directory. Persistence is turned on the same way, and the
      // transcript is moved into this call's directory once the call returns its session id.
      let claudeSessionDir: string | null = null;
      if (binary === "claude" && config.pi_session_root && options.args) {
        claudeSessionDir = join(config.pi_session_root, minted);
        observedOptions = { ...options, args: options.args.filter((arg) => arg !== "--no-session") };
        claudeSessionCalls += 1;
        claudeSessionCallIds.push(minted);
      }
      // The engine's own id when it tagged the call, so a context.selection event and the model
      // events of the same invocation share one call_id; the driver's own id when it did not.
      const callId = meta.invocationId ?? minted;
      const stage = typeof meta.stage === "string" && meta.stage ? meta.stage : "untagged";
      const retryIdentity = plannerRetryIdentity(options, meta.invocationId, stage);
      let activePlannerCall: ActivePlannerCall | null = null;
      let retryOf: PendingPlannerTimeout | null = null;
      if (retryIdentity) {
        activePlannerCall = { identity: retryIdentity, concurrent: false };
        for (const active of activePlannerCalls) {
          if (!samePlannerRetryIdentity(active.identity, retryIdentity)) continue;
          active.concurrent = true;
          activePlannerCall.concurrent = true;
        }
        if (activePlannerCall.concurrent) {
          // Once this exact invocation identity has overlapped, order cannot establish which
          // operation a later call belongs to. Keep every failure unresolved for that identity.
          if (!ambiguousPlannerRetryIdentities.some((entry) => samePlannerRetryIdentity(entry, retryIdentity))) {
            ambiguousPlannerRetryIdentities.push(retryIdentity);
          }
          for (let index = pendingPlannerTimeouts.length - 1; index >= 0; index -= 1) {
            if (samePlannerRetryIdentity(pendingPlannerTimeouts[index].identity, retryIdentity)) {
              pendingPlannerTimeouts.splice(index, 1);
            }
          }
        }
        const ambiguous = ambiguousPlannerRetryIdentities.some((entry) => samePlannerRetryIdentity(entry, retryIdentity));
        if (!ambiguous) {
          const pendingIndex = pendingPlannerTimeouts.findIndex((entry) =>
            samePlannerRetryIdentity(entry.identity, retryIdentity));
          if (pendingIndex !== -1) retryOf = pendingPlannerTimeouts.splice(pendingIndex, 1)[0] ?? null;
        }
        activePlannerCalls.push(activePlannerCall);
      }
      const view = describeInvocation(observedOptions as unknown as Record<string, unknown>, resolveBinary);
      const route = config.runner === "mock" ? "mock" : view.route;
      observedRoutes.add(route);
      const state: CallState = { callId, runnerCallId: minted, view, route, final: null, attemptSessions: [] };
      calls.set(minted, state);
      modelCallIds.add(callId);
      runnerCalls.push({ callId, stage });
      const callOrder = ++contextLifecycleOrder;
      const mappingContexts = contextsByCallId.get(callId) ?? [];
      if (config.trace_mode !== "off" && !contextBufferExhausted && mappingContexts.length > 0
          && !promptRetentionFailed.has(callId)) {
        const prompts = promptsByCallId.get(callId) ?? [];
        if (mappingPromptRecords + 1 > MAX_MAPPING_RETAINED_PROMPT_RECORDS
            || mappingPromptChars + view.prompt.length > MAX_MAPPING_RETAINED_PROMPT_CHARS) {
          // Drop this ID's earlier prompts too: keeping a prefix of its lifecycle would let a
          // later conflicting call disappear from the exact-mapping decision.
          for (const retained of prompts) mappingPromptChars -= retained.prompt.length;
          mappingPromptRecords -= prompts.length;
          promptsByCallId.delete(callId);
          promptRetentionFailed.add(callId);
        } else {
          prompts.push({ prompt: view.prompt, order: callOrder });
          promptsByCallId.set(callId, prompts);
          mappingPromptChars += view.prompt.length;
          mappingPromptRecords += 1;
        }
      }
      // Read source at the actual call boundary, not after a scanner had more time to mutate its
      // workspace. Final attribution remains buffered until every reuse of this logical ID is
      // known; a later conflicting prompt must be able to make the mapping conservative.
      if (!promptRetentionFailed.has(callId)) {
        for (const context of mappingContexts) {
          if (context.order >= callOrder) continue;
          snapshotContextSources(context.record);
        }
      }
      // The runner uses meta only for its hooks. A driver-owned key prevents concurrent or
      // retried calls with the same harness ID from replacing each other's observation state.
      const invocation = { ...observedOptions, meta: { ...meta, invocationId: minted } };
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
            runner_call_id: minted,
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
      let returned: PiResult | null = null;
      let callFailed = false;
      let plannerTimedOut = false;
      try {
        const result = await baseRunner.runPi(invocation);
        returned = result;
        if (result.code !== 0) {
          modelFailures += 1;
          callFailed = true;
          plannerTimedOut = isPlannerTimeoutMessage(result.stderr || result.stdout || `pi exited with code ${result.code}`);
        }
        const elapsed = Date.now() - began;
        if (runnerHooks === null) await emitUnhookedResponse(state, result, null, elapsed);
        else await emitHookedResponse(state, result, null, elapsed);
        return result;
      } catch (error) {
        modelFailures += 1;
        callFailed = true;
        const message = error instanceof Error ? error.message : String(error);
        plannerTimedOut ||= isPlannerTimeoutMessage(message);
        const elapsed = Date.now() - began;
        if (runnerHooks === null) await emitUnhookedResponse(state, null, error, elapsed);
        else await emitHookedResponse(state, null, error, elapsed);
        throw error;
      } finally {
        // Here rather than after the return, so a call that threw keeps its attempts' transcripts.
        if (claudeSessionDir !== null) archiveClaudeSessions(state, minted, returned, claudeSessionDir);
        calls.delete(minted);
        if (activePlannerCall) {
          const activeIndex = activePlannerCalls.indexOf(activePlannerCall);
          if (activeIndex !== -1) activePlannerCalls.splice(activeIndex, 1);
        }
        const ambiguous = retryIdentity !== null && ambiguousPlannerRetryIdentities.some((entry) =>
          samePlannerRetryIdentity(entry, retryIdentity));
        // Count every planner timeout, including one too thin to fingerprint. A native retry
        // declaration cannot safely recover some other pair while an unattributed planner
        // timeout is present in the same run.
        if (callFailed && plannerTimedOut && stage === "planner") plannerTimeoutFailures += 1;
        if (retryOf && !callFailed && !ambiguous) {
          plannerRecoveryCandidates.push({
            invocation_id: retryIdentity!.invocationId,
            failed_runner_call_id: retryOf.runnerCallId,
            recovery_runner_call_id: minted,
          });
        } else if (!retryOf && callFailed && plannerTimedOut && retryIdentity && !ambiguous) {
          pendingPlannerTimeouts.push({ identity: retryIdentity, runnerCallId: minted });
        }
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
      if (config.trace_mode === "off") {
        try {
          if (typeof record.invocationId === "string") contextCallIds.add(record.invocationId);
        } catch {
          contextSnapshotFailures += 1;
        }
        return;
      }
      const sourceTimestamp = nowIso();
      const captured = snapshotContextRecord(record);
      if (captured.record === null) {
        // A hostile getter or proxy is an observation hole, not a reason to break the scan. A
        // pathless partial event makes the loss visible to coverage diagnostics; where the ID
        // was readable it is retained so the hole belongs to the right invocation.
        contextSnapshotFailures += 1;
        if (captured.callId !== null) contextCallIds.add(captured.callId);
        void observer.emit({
          type: "context.selection",
          capture_status: "partial",
          ...(captured.callId !== null ? { call_id: captured.callId } : {}),
          metadata: {
            source: "harness_emitted",
            source_timestamp: sourceTimestamp,
            source_timestamp_of: "harness_context_callback",
            capture_gap: "context_snapshot_failed",
          },
        });
        return;
      }
      const snapshot = captured.record;
      if (typeof snapshot.invocationId === "string") {
        contextCallIds.add(snapshot.invocationId);
      }
      const snapshotId = snapshot.invocationId;
      const context = {
        record: snapshot,
        order: ++contextLifecycleOrder,
        sourceTimestamp,
        beforeFirstCall: typeof snapshotId === "string" && !modelCallIds.has(snapshotId),
      };
      if (contextBufferExhausted) {
        void emitContextRecord(snapshot, null, sourceTimestamp);
        return;
      }
      if (bufferedContext.length >= MAX_BUFFERED_CONTEXT_RECORDS) {
        // Release the whole buffer in callback order and stop attempting exact mapping. Partial
        // retention could make a later duplicate or conflicting lifecycle invisible.
        contextBufferExhausted = true;
        for (const pending of bufferedContext) {
          void emitContextRecord(pending.record, null, pending.sourceTimestamp);
        }
        bufferedContext.length = 0;
        contextsByCallId.clear();
        promptsByCallId.clear();
        mappingPromptChars = 0;
        mappingPromptRecords = 0;
        void emitContextRecord(snapshot, null, sourceTimestamp);
        return;
      }
      bufferedContext.push(context);
      if (typeof snapshot.invocationId === "string") {
        const siblings = contextsByCallId.get(snapshot.invocationId) ?? [];
        siblings.push(context);
        contextsByCallId.set(snapshot.invocationId, siblings);
      }
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

  const researchPreflightResult = imageState ? await researchPreflight(imageState) : null;

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
  if (imageState) {
    // The private agent directory holds the credential and whatever Pi wrote beside it. It goes
    // as soon as no model call can need it, and whether it really went is recorded.
    try {
      rmSync(imageState.agentDir, { recursive: true, force: true });
    } catch {
      // Recorded below as not removed.
    }
    imageState.credential.removed = !existsSync(imageState.agentDir);
  }

  // A v1 call ID is only a logical correlation key and can be reused by outer retries or even
  // concurrent work. Exact mapping is proved only for one context record that preceded the
  // first call and whose every joined call carried the same prompt. Duplicate records, a late
  // callback, conflicting prompts, and a record with no call all stay unlocated. Events retain
  // callback order even though they are emitted here, after the lifecycle is known.
  for (const context of bufferedContext) {
    const callId = context.record.invocationId;
    const siblingContexts = typeof callId === "string" ? contextsByCallId.get(callId) ?? [] : [];
    const calls = typeof callId === "string" ? promptsByCallId.get(callId) ?? [] : [];
    const firstPrompt = calls[0]?.prompt;
    const unambiguous = typeof callId === "string" && !promptRetentionFailed.has(callId)
      && siblingContexts.length === 1 && calls.length > 0
      && context.beforeFirstCall
      && calls.every((call) => call.prompt === firstPrompt);
    await emitContextRecord(context.record, unambiguous ? firstPrompt ?? null : null,
                            context.sourceTimestamp);
  }

  const plannerTimeoutRetryDeclarations = declaredPlannerTimeoutRetries(summary, config.mode);
  // Neither side is sufficient alone: equal request fingerprints are allowed for independent
  // calls, while a native note without the matching observed lifecycle could describe a retry
  // this runner never saw. Any ambiguity leaves every raw failure unresolved.
  const contextualPlannerRecoveryCandidates = plannerRecoveryCandidates.filter((candidate) =>
    contextCallIds.has(candidate.invocation_id));
  const plannerTimeoutRecoveries = plannerTimeoutRetryDeclarations === 1
    && plannerTimeoutFailures === 1
    && plannerRecoveryCandidates.length === 1
    && contextualPlannerRecoveryCandidates.length === 1
    ? plannerRecoveryCandidates
    : [];
  const recoveredModelFailures = plannerTimeoutRecoveries.length;
  const unrecoveredModelFailures = modelFailures - recoveredModelFailures;

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
  const untagged = runnerCalls.filter(({ callId }) => !contextCallIds.has(callId));
  const untaggedCalls = untagged.length;
  const untaggedByStage: Record<string, number> = {};
  for (const { stage } of untagged) {
    untaggedByStage[stage] = (untaggedByStage[stage] ?? 0) + 1;
  }
  const stagesListed = Object.entries(untaggedByStage).sort()
    .map(([stage, count]) => `${stage} ${count}`).join(", ");
  // What this run could not see, for this harness build. Each entry is a category nothing was
  // observed in; none of them is evidence that the thing did not happen.
  const unavailable = [
    "tool.start",
    "tool.end",
    ...(engineHooks === null ? ["finding.candidate"] : []),
    // The consensus judge is the only validation stage. The engine runs it in pr mode and only
    // when consensus is configured, and this driver never passes `consensus`, so neither mode it
    // is used in has a validation stage at all, which is a different statement from not seeing one.
    // The reason differs by mode: a bootstrap scan has no such stage, and a pr scan is never given
    // the judge.
    ...(engineHooks === null
      ? ["finding.validation"]
      : config.mode === "bootstrap"
        ? ["finding.validation (not applicable: a bootstrap scan runs no validation stage)"]
        : ["finding.validation (not applicable: the consensus judge is the only validation stage, and this "
          + "driver never configures consensus)"]),
    ...(engineHooks === null ? ["finding.filtered"] : []),
    ...(imageState
      ? ["model retries inside the harness runner"]
      : runnerHooks === null
        ? ["model retries inside the harness runner", "token usage"]
        : ["token usage on the pi route"]),
    ...(engineHooks === null || untaggedCalls === 0
      ? []
      : [`context.selection for ${untaggedCalls} of ${modelCallIds.size} model invocations `
        + `(the harness did not report supplied spans for these calls; by the stage it tagged them: ${stagesListed})`]),
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
    // Historical runner-invocation failures remain intact. Recovery is a separate, explicitly
    // attributed count, and status readers use the unresolved remainder.
    model_call_failures: modelFailures,
    model_call_failures_recovered: recoveredModelFailures,
    model_call_failures_unrecovered: unrecoveredModelFailures,
    planner_timeout_retry_declarations: plannerTimeoutRetryDeclarations,
    planner_timeout_failures_observed: plannerTimeoutFailures,
    planner_timeout_recovery_candidates: plannerRecoveryCandidates.length,
    planner_timeout_recoveries: plannerTimeoutRecoveries,
    pi_session_calls: piSessionCalls,
    pi_session_call_ids: piSessionCallIds,
    // Claude transcripts are moved into the same per-call directories, so the adapter registers
    // them with the pi ones. These fields say which calls were claude and which transcripts were
    // not found.
    claude_session_calls: claudeSessionCalls,
    claude_session_call_ids: claudeSessionCallIds,
    claude_session_missing: claudeSessionMissing,
    session_manifest: sessionManifest,
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
    // Snapshotting happens inside the callback so caller mutation cannot rewrite history. A
    // throwing getter/proxy is contained and counted here rather than escaping into the scan.
    driver_context_snapshot_failures: contextSnapshotFailures,
    // Runner invocations, including outer retries that share a harness call ID and its context.
    // An untagged call is an uninstrumented one, never a call that was given no context.
    model_calls_with_context: runnerCalls.length - untaggedCalls,
    model_calls_without_context: untaggedCalls,
    // The same calls by the stage the engine tagged each one with, "untagged" when it named none.
    model_calls_without_context_by_stage: Object.fromEntries(Object.entries(untaggedByStage).sort()),
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
    // The image runtime's identities and route, absent on the local runtime. Versions are what
    // the image's own receipt and the processes themselves report; file digests are of the
    // files this process actually loaded.
    ...(imageState ? {
      runtime: {
        kind: "oci_image",
        receipt: imageState.receipt,
        receipt_error: imageState.receiptError,
        node_version: process.version,
        pi_version: imageState.piVersion,
        pi_version_error: imageState.piVersionError,
        files: imageState.files,
      },
      pi_route: {
        route: PI_OCI_ROUTE,
        provider: imageState.image.pi_provider,
        model_id: imageState.image.pi_model_id,
        requested: config.model,
        thinking_level: imageState.image.thinking_level,
        tools: imageTools(imageState.image),
        extensions: [imageState.image.pi_extension,
          ...(imageState.image.pi_synthetic_extension ? [imageState.image.pi_synthetic_extension] : [])],
        synthetic: imageState.image.synthetic !== null,
        credential: imageState.credential,
        research: { search: imageState.image.research.search, journal_dir: imageState.image.research.journal_dir,
          preflight: researchPreflightResult },
      },
      pi_calls: piCallSummary,
    } : {}),
    summary,
    error: failure,
    trace: {
      mode: config.trace_mode,
      path: config.trace_mode === "off" ? null : config.trace_path ?? null,
      events_written: eventsWritten,
      state: observer.getState(),
      flush_timed_out: flushTimedOut,
      unavailable,
      tool_dispatch_note: imageState
        ? "Tool dispatch happens inside the Pi subprocess. Pi's own JSON stream reports each tool execution, "
          + "counted under pi_calls.tool_executions; no tool event is emitted into this trace, and neither count "
          + "shows that a tool's result entered or shaped a model response."
        : "Tool dispatch happens inside the model CLI subprocess, which this driver spawns but "
          + "cannot see into. No tool event is emitted, and no absence of tool use is established.",
      usage_note: imageState
        ? "Token usage and the cost estimate are summed from the usage Pi attached to each assistant message in its "
          + "JSON stream: Pi's own accounting, with a cost Pi computes from its catalog prices, never a bill."
        : runnerHooks === null
        ? "This harness build exports no runner hooks, so no attempt, no token count and no cost estimate was observed."
        : "Token usage and the cost estimate are read from the claude CLI's own json result object. The pi route "
          + "prints no usage and the mock runner calls no model, so a run on either reports none; an absent count "
          + "is not a measurement of zero.",
      context_note: engineHooks === null
        ? "Context selection is read from the harness's own progress notes, which describe the scan rather than "
          + "report the prompt; nothing here is the engine's actual selection."
        : `The engine reported the context it supplied for ${modelCallIds.size - untaggedCalls} of `
          + `${modelCallIds.size} model invocations. A model.request with no context.selection is an `
          + "uninstrumented call, not a call that was given no context.",
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
