// SASTbench driver for the securevibes-agent / Fieldglass engine family.
//
// It runs the harness's own engine (runRuntimeScan) unchanged, injecting only the
// harness's default model runner wrapped by the opt-in observer. It records what the
// engine exposes at that boundary: the outgoing CLI request per logical model call, the
// returned stdout/stderr/exit code, self-reported context selection notes, and the
// findings the engine finally wrote. Retries inside the harness runner, candidate
// creation, validation, and filtering are not observable here and are declared so.
//
// Invoked by sastbench.adapters.llm_harness with the harness's own tsx:
//   <harness>/node_modules/.bin/tsx llm_harness_driver.mts --config <driver-config.json>

import { appendFileSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

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

type PiResult = { code: number; stdout: string; stderr: string };
type PiRunner = { runPi(options: { args?: string[]; request?: unknown; cwd: string; timeoutMs: number; env: NodeJS.ProcessEnv }): Promise<PiResult> };

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

async function main(): Promise<void> {
  const configPath = argValue("config");
  if (!configPath) throw new Error("--config <path> is required");
  const config = JSON.parse(readFileSync(configPath, "utf8")) as DriverConfig;
  const startedAt = nowIso();
  const started = Date.now();

  const engineModule = await import(pathToFileURL(join(config.harness_root, config.engine_entry)).href);
  const runnerModule = await import(pathToFileURL(join(config.harness_root, config.runner_entry)).href);
  const observerModule = await import(pathToFileURL(config.observer_sdk).href);

  const baseRunner: PiRunner = config.runner === "mock"
    ? (await import(pathToFileURL(join(config.harness_root, config.mock_entry)).href)).createDeterministicTestLlmRunner()
    : runnerModule.createDefaultPiRunner();
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
  // Which CLI actually served each call. The tool policy differs by route, and neither
  // route's tool dispatch happens in this process, so this records what was asked for,
  // never what the CLI did with it.
  const observedRoutes = new Set<string>();
  const observedRunner: PiRunner = {
    async runPi(options) {
      modelCalls += 1;
      const callId = `call-${modelCalls}`;
      const view = describeInvocation(options as unknown as Record<string, unknown>, resolveBinary);
      observedRoutes.add(config.runner === "mock" ? "mock" : view.route);
      const requestedModel = view.model;
      const began = Date.now();
      await observer.emit({
        type: "model.request",
        capture_status: "complete",
        call_id: callId,
        metadata: {
          model_requested: requestedModel,
          thinking: view.thinking,
          route: config.runner === "mock" ? "mock" : view.route,
          prompt_chars: view.promptChars,
          timeout_ms: options.timeoutMs,
          retries_observable: false,
        },
        content: view.content,
      });
      try {
        const result = await baseRunner.runPi(options);
        if (result.code !== 0) modelFailures += 1;
        await observer.emit({
          type: "model.response",
          capture_status: "complete",
          call_id: callId,
          duration_ms: Date.now() - began,
          metadata: {
            model_requested: requestedModel,
            exit_code: result.code,
            stdout_chars: result.stdout.length,
            stderr_chars: result.stderr.length,
            usage_available: false,
          },
          content: { stdout: result.stdout, stderr: result.stderr },
        });
        return result;
      } catch (error) {
        modelFailures += 1;
        await observer.emit({
          type: "model.response",
          capture_status: "partial",
          call_id: callId,
          duration_ms: Date.now() - began,
          metadata: { model_requested: requestedModel, exception: error instanceof Error ? error.message : String(error) },
        });
        throw error;
      }
    },
  };

  let progressNotes = 0;
  const progressReporter = (note: string): void => {
    progressNotes += 1;
    appendFileSync(config.progress_path, `${nowIso()} ${note}\n`);
    if (/(^|\s)file=/.test(note)) {
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
      ...(config.qmd_profile ? { qmdProfile: config.qmd_profile } : {}),
      ...(typeof config.llm_max_files === "number" ? { llmMaxFiles: config.llm_max_files } : {}),
      ...(typeof config.llm_timeout_ms === "number" ? { llmTimeoutMs: config.llm_timeout_ms } : {}),
      ...(config.specialist_ids ? { specialistIds: config.specialist_ids } : {}),
      ...(config.base_ref ? { baseRef: config.base_ref } : {}),
      ...(config.head_ref ? { headRef: config.head_ref } : {}),
    });
    const record = summary as { newFindings?: Array<Record<string, unknown>>; updatedFindings?: Array<Record<string, unknown>> };
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
            stage,
            vulnerability_class: finding.vulnerabilityClass ?? null,
            severity: finding.severity ?? null,
            component: finding.component ?? null,
            file_path: finding.filePath ?? null,
            scanner_sources: finding.scannerSources ?? null,
            confidence: finding.confidence ?? null,
            status: finding.status ?? null,
          },
        });
      }
    }
  } catch (error) {
    failure = { name: error instanceof Error ? error.name : "Error", message: error instanceof Error ? error.message : String(error) };
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
  const output = {
    schema_version: "2.0",
    driver_version: "2.1.0",
    harness: { root: config.harness_root, package_version: packageVersion, ...gitHead(config.harness_root) },
    model: config.model,
    runner: config.runner,
    mode: config.mode,
    started_at: startedAt,
    finished_at: nowIso(),
    wall_ms: Date.now() - started,
    model_calls: modelCalls,
    model_call_failures: modelFailures,
    observed_routes: [...observedRoutes].sort(),
    progress_notes: progressNotes,
    summary,
    error: failure,
    trace: {
      mode: config.trace_mode,
      path: config.trace_mode === "off" ? null : config.trace_path ?? null,
      events_written: eventsWritten,
      state: observer.getState(),
      flush_timed_out: flushTimedOut,
      unavailable: ["tool.start", "tool.end", "finding.candidate", "finding.validation", "finding.filtered",
                    "model retries inside the harness runner", "token usage"],
      tool_dispatch_note: "Tool dispatch happens inside the model CLI subprocess, which this driver spawns but "
        + "cannot see into. No tool event is emitted, and no absence of tool use is established.",
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
      writeFileSync(outputPath, JSON.stringify({ schema_version: "2.0", driver_version: "2.1.0", summary: null,
        error: { name: "DriverFailure", message } }, null, 2));
    } catch {
      // Nothing else to record; the exit code carries the failure.
    }
  }
  console.error(message);
  process.exit(1);
});
