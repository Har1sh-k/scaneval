// The raw Pi runner of the SV-Agent image runtime (config.runtime = "oci_image").
//
// The harness's scan stages build pi argv of their own (`-p --no-session --model M --thinking T
// <prompt>`) and hand it to whatever runner the engine was given. Upstream's default runner execs
// that argv as is. This runner replaces only the innermost exec: the driver composes it under the
// harness's own createRetryingPiRunner(createIsolatedPiRunner(...)), exactly the way upstream's
// createDefaultPiRunner composes its exec, so retry classification, per-call temporary working
// directories and argv NUL sanitizing stay the harness's. No stage, prompt or selection logic is
// changed here.
//
// What it changes about each invocation, all of it transport:
//
//   * The stage's argv is parsed strictly. Only the flags upstream stages are known to pass are
//     accepted; anything else fails the call rather than being forwarded or dropped silently.
//   * The model route must be the one the run pinned. A stage asking for another model fails;
//     there is no model or provider fallback.
//   * The reasoning level is the run's configured level, whatever the stage asked for; the
//     stage's request is reported beside it.
//   * The prompt travels on stdin instead of argv, so no prompt is ever on a command line and no
//     argv length limit applies. Pi trims piped stdin, so leading and trailing whitespace of a
//     prompt is not delivered; upstream's isolation wrapper has already rewritten any NUL byte as
//     the two characters `\0`, which is preserved.
//   * Pi runs in `--mode json` so the final assistant message, its stop reason, the provider and
//     model Pi addressed, usage, and every tool execution Pi itself reports are read off the
//     stream. The engine receives exactly what `--print` would have printed: each text block of
//     the last assistant message followed by a newline, with the same nonzero exit and stderr
//     message on an error, abort or length stop.
//   * Tools are an explicit allowlist: `--no-extensions -e <image-owned extension>` and
//     `--tools <names>` (or `--no-tools` when none), with MCP, skills, prompt templates, themes,
//     context files and project trust all disabled, and a private agent directory.
//   * The environment is built from an allowlist, never inherited: no provider API key and no
//     credential variable reaches Pi. Pi reads its OAuth credential from the private agent dir.

export const PI_OCI_ROUTE = "pi-oci";
export const PI_OCI_RUNNER_VERSION = "1.0.0";
export const THINKING_LEVELS = ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const;
// Generous by design: JSON mode carries every delta and tool result, so it is many times larger
// than the text the engine receives. The stage's own output bound is applied to that text.
const DEFAULT_STREAM_LIMIT = 256 * 1024 * 1024;

type ExecResult = { code: number; stdout: string; stderr: string };
type Exec = (command: string, args: string[], options: {
  cwd?: string; timeoutMs?: number; env?: Record<string, string | undefined>; abortSignal?: AbortSignal;
  stdin?: string; maxOutputBytes?: number;
}) => Promise<ExecResult>;

export interface PiInvocation {
  args?: string[];
  cwd: string;
  timeoutMs: number;
  env?: Record<string, string | undefined>;
  abortSignal?: AbortSignal;
  maxOutputBytes?: number;
  meta?: Record<string, unknown>;
}

export interface StageArgs {
  print: boolean;
  noSession: boolean;
  model: string | null;
  thinking: string | null;
  prompt: string;
  /** Stage flags this runner replaces with its own explicit policy (e.g. --no-tools). */
  replaced: string[];
}

export interface PiCallObservation {
  route: string;
  model_requested_by_stage: string | null;
  thinking_requested_by_stage: string | null;
  thinking_applied: string;
  provider_addressed: string | null;
  model_addressed: string | null;
  stop_reason: string | null;
  exit_code: number;
  usage: { input: number; output: number; cacheRead: number; cacheWrite: number; cost: number } | null;
  assistant_messages: number;
  tool_executions: Array<{ name: string; is_error: boolean }>;
  stream_records: number;
  stream_unparsed_records: number;
  prompt_chars: number;
  replaced_stage_flags: string[];
  session_dir_used: boolean;
}

export interface PiOciRunnerOptions {
  exec: Exec;
  piBinary: string;
  provider: string;
  modelId: string;
  /** The route the harness stages must ask for, `<provider>/<modelId>`. */
  requestedModel: string;
  thinkingLevel: string;
  agentDir: string;
  extensions: string[];
  tools: string[];
  /** Nonsecret environment for every Pi process; nothing else is inherited. */
  environment: Record<string, string>;
  /** Where per-call session directories may be; a session dir outside it is refused. */
  sessionRoot?: string | null;
  streamLimitBytes?: number;
  onCall?: (observation: PiCallObservation) => void;
}

const BOOLEAN_FLAGS = new Map<string, keyof StageArgs | null>([
  ["-p", "print"], ["--print", "print"], ["--no-session", "noSession"],
  // Upstream's go-evidence stage passes these. The runner's own explicit policy below supersedes
  // them; each is reported as replaced rather than forwarded.
  ["--no-tools", null], ["--no-extensions", null], ["--no-skills", null],
]);
const VALUE_FLAGS = new Map<string, "model" | "thinking">([["--model", "model"], ["--thinking", "thinking"]]);

function flagName(word: string): string {
  return word.length > 40 ? `${word.slice(0, 40)}...` : word;
}

/** Parse what a harness stage passed; the last word is always the prompt. */
export function parseStageArgs(args: unknown): StageArgs {
  if (!Array.isArray(args) || args.length === 0 || !args.every((word) => typeof word === "string")) {
    throw new Error("the harness stage passed no pi argv to the image runner");
  }
  const words = args as string[];
  const parsed: StageArgs = { print: false, noSession: false, model: null, thinking: null,
    prompt: words[words.length - 1], replaced: [] };
  for (let index = 0; index < words.length - 1; index += 1) {
    const word = words[index];
    if (BOOLEAN_FLAGS.has(word)) {
      const key = BOOLEAN_FLAGS.get(word);
      if (key === "print") parsed.print = true;
      else if (key === "noSession") parsed.noSession = true;
      else parsed.replaced.push(word);
      continue;
    }
    const valueKey = VALUE_FLAGS.get(word);
    if (valueKey) {
      if (index + 1 >= words.length - 1) throw new Error(`the harness stage passed ${word} without a value`);
      parsed[valueKey] = words[index + 1];
      index += 1;
      continue;
    }
    // Only the flag's name is quoted: a positional word here could be prompt text.
    throw new Error(word.startsWith("-")
      ? `the harness stage passed a pi flag this runner does not support: ${flagName(word)}`
      : "the harness stage passed more than one positional pi argument");
  }
  if (!parsed.print) throw new Error("the harness stage did not ask for print mode (-p)");
  if (!parsed.prompt) throw new Error("the harness stage passed an empty prompt");
  return parsed;
}

/** The exact argv Pi is started with. Nothing in it comes from the prompt. */
export function buildPiArgs(options: Pick<PiOciRunnerOptions, "provider" | "modelId" | "thinkingLevel"
  | "extensions" | "tools">, stage: Pick<StageArgs, "noSession">): string[] {
  return [
    "--mode", "json",
    "--provider", options.provider,
    "--model", options.modelId,
    "--thinking", options.thinkingLevel,
    "--no-extensions",
    ...options.extensions.flatMap((path) => ["-e", path]),
    ...(options.tools.length > 0 ? ["--tools", options.tools.join(",")] : ["--no-tools"]),
    "--no-mcp", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve",
    ...(stage.noSession ? ["--no-session"] : []),
  ];
}

interface ParsedStream {
  finalMessage: Record<string, unknown> | null;
  assistantMessages: number;
  providers: Set<string>;
  models: Set<string>;
  usage: { input: number; output: number; cacheRead: number; cacheWrite: number; cost: number } | null;
  toolExecutions: Array<{ name: string; is_error: boolean }>;
  records: number;
  unparsed: number;
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

/** Read Pi's JSONL event stream. Split on LF only, as Pi's own framing rules require. */
export function parsePiJsonStream(stdout: string): ParsedStream {
  const parsed: ParsedStream = { finalMessage: null, assistantMessages: 0, providers: new Set(), models: new Set(),
    usage: null, toolExecutions: [], records: 0, unparsed: 0 };
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!line) continue;
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(line);
    } catch {
      parsed.unparsed += 1;
      continue;
    }
    parsed.records += 1;
    if (record?.type === "message_end" && record.message && typeof record.message === "object") {
      const message = record.message as Record<string, unknown>;
      parsed.finalMessage = message;
      if (message.role !== "assistant") continue;
      parsed.assistantMessages += 1;
      if (typeof message.provider === "string") parsed.providers.add(message.provider);
      if (typeof message.model === "string") parsed.models.add(message.model);
      const usage = message.usage as Record<string, unknown> | undefined;
      if (usage && typeof usage === "object") {
        const total = parsed.usage ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0 };
        total.input += count(usage.input);
        total.output += count(usage.output);
        total.cacheRead += count(usage.cacheRead);
        total.cacheWrite += count(usage.cacheWrite);
        total.cost += count((usage.cost as Record<string, unknown> | undefined)?.total);
        parsed.usage = total;
      }
    } else if (record?.type === "tool_execution_end") {
      parsed.toolExecutions.push({ name: typeof record.toolName === "string" ? record.toolName : "unknown",
        is_error: record.isError === true });
    }
  }
  return parsed;
}

/** What `pi --print` would have returned for the same run, derived from the JSON stream. */
export function printEquivalent(stream: ParsedStream, exitCode: number, stderr: string): ExecResult {
  const message = stream.finalMessage;
  if (!message || message.role !== "assistant") {
    return { code: exitCode !== 0 ? exitCode : 1, stdout: "",
      stderr: stderr || "pi produced no final assistant message" };
  }
  const stopReason = message.stopReason;
  if (stopReason === "error" || stopReason === "aborted") {
    const reason = typeof message.errorMessage === "string" && message.errorMessage
      ? message.errorMessage : `Request ${String(stopReason)}`;
    return { code: 1, stdout: "", stderr: stderr ? `${stderr}\n${reason}` : reason };
  }
  const blocks = Array.isArray(message.content) ? message.content as Array<Record<string, unknown>> : [];
  const text = blocks.filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => `${block.text as string}\n`).join("");
  if (stopReason === "length") {
    const warning = "Response was truncated: the model reached its output token limit.";
    return { code: 1, stdout: text, stderr: stderr ? `${stderr}\n${warning}` : warning };
  }
  return { code: exitCode, stdout: text, stderr };
}

function insideRoot(path: string, root: string): boolean {
  const normalizedRoot = root.endsWith("/") ? root : `${root}/`;
  return path.startsWith(normalizedRoot) && !path.split("/").includes("..");
}

/** The raw runner: one Pi process per invocation, for the harness's own wrappers to compose. */
export function createPiOciRawRunner(options: PiOciRunnerOptions) {
  if (!THINKING_LEVELS.includes(options.thinkingLevel as typeof THINKING_LEVELS[number])) {
    throw new Error(`thinking level ${JSON.stringify(options.thinkingLevel)} is not one Pi accepts`);
  }
  if (options.requestedModel !== `${options.provider}/${options.modelId}`) {
    throw new Error("the pinned model route must be <provider>/<model>");
  }
  return {
    async runPi(invocation: PiInvocation): Promise<ExecResult & { binary: string; outputFormat: "text"; piStream: PiCallObservation }> {
      const stage = parseStageArgs(invocation.args);
      if (stage.model !== options.requestedModel) {
        throw new Error(`the harness stage asked for model route ${JSON.stringify(stage.model)}, but this run pins `
          + `${options.requestedModel}; no other route is used`);
      }
      const environment: Record<string, string> = { ...options.environment, PI_CODING_AGENT_DIR: options.agentDir };
      const sessionDir = invocation.env?.PI_CODING_AGENT_SESSION_DIR;
      let sessionDirUsed = false;
      if (typeof sessionDir === "string" && sessionDir && !stage.noSession) {
        if (!options.sessionRoot || !insideRoot(sessionDir, options.sessionRoot)) {
          throw new Error("a pi session directory outside the run's session root was requested");
        }
        environment.PI_CODING_AGENT_SESSION_DIR = sessionDir;
        sessionDirUsed = true;
      }
      const args = buildPiArgs(options, stage);
      const result = await options.exec(options.piBinary, args, {
        cwd: invocation.cwd,
        timeoutMs: invocation.timeoutMs,
        env: environment,
        stdin: stage.prompt,
        maxOutputBytes: options.streamLimitBytes ?? DEFAULT_STREAM_LIMIT,
        ...(invocation.abortSignal ? { abortSignal: invocation.abortSignal } : {}),
      });
      const stream = parsePiJsonStream(result.stdout);
      const printed = printEquivalent(stream, result.code, result.stderr);
      const observation: PiCallObservation = {
        route: PI_OCI_ROUTE,
        model_requested_by_stage: stage.model,
        thinking_requested_by_stage: stage.thinking,
        thinking_applied: options.thinkingLevel,
        provider_addressed: stream.providers.size === 1 ? [...stream.providers][0] : null,
        model_addressed: stream.models.size === 1 ? [...stream.models][0] : null,
        stop_reason: typeof stream.finalMessage?.stopReason === "string" ? stream.finalMessage.stopReason as string : null,
        exit_code: printed.code,
        usage: stream.usage,
        assistant_messages: stream.assistantMessages,
        tool_executions: stream.toolExecutions,
        stream_records: stream.records,
        stream_unparsed_records: stream.unparsed,
        prompt_chars: stage.prompt.length,
        replaced_stage_flags: stage.replaced,
        session_dir_used: sessionDirUsed,
      };
      options.onCall?.(observation);
      if (invocation.maxOutputBytes !== undefined && Buffer.byteLength(printed.stdout, "utf8") > invocation.maxOutputBytes) {
        throw new Error("Command output exceeded its byte limit.");
      }
      return { ...printed, binary: "pi", outputFormat: "text", piStream: observation };
    },
  };
}
