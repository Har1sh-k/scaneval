// DIAGNOSTIC ONLY. A deterministic, in-process fake model provider for exercising the SV-Agent
// open-context route end to end without calling any model. Nothing it produces is scanner
// evidence, and a run that loads it is recorded as diagnostic by the adapter.
//
// The runner loads this extension only when the adapter configuration selects the synthetic
// model route explicitly (`scaneval-synthetic/deterministic-open-context`). It registers that one
// provider and model; it registers no tool.
//
// Each Pi invocation is two turns. The first turn issues the tool calls named in
// $SCANEVAL_SYNTHETIC_TOOL_CALLS (a JSON array of {name, arguments}) in one assistant message.
// Once any tool result is in the transcript, the second turn answers with the harness's own
// deterministic mock response for the original prompt, loaded from
// $SCANEVAL_SYNTHETIC_HARNESS_MOCK, so the engine receives the format it expects.

import {
  createAssistantMessageEventStream,
  type AssistantMessage, type AssistantMessageEventStream, type Api, type Model,
  type SimpleStreamOptions, type TranscriptContext,
} from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { pathToFileURL } from "node:url";

export const SYNTHETIC_PROVIDER = "scaneval-synthetic";
export const SYNTHETIC_MODEL = "deterministic-open-context";

type Block = { type: string; text?: string };

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return (content as Block[]).filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => block.text).join("\n");
}

async function finalText(prompt: string): Promise<string> {
  const mock = process.env.SCANEVAL_SYNTHETIC_HARNESS_MOCK;
  if (!mock) return '{"findings":[]}';
  const module = await import(pathToFileURL(mock).href);
  const runner = module.createDeterministicTestLlmRunner();
  const result = await runner.runPi({ args: ["-p", prompt], cwd: "/tmp", timeoutMs: 60_000, env: {} });
  return typeof result?.stdout === "string" ? result.stdout : '{"findings":[]}';
}

function plannedCalls(): Array<{ name: string; arguments: Record<string, unknown> }> {
  try {
    const parsed = JSON.parse(process.env.SCANEVAL_SYNTHETIC_TOOL_CALLS ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((call) => call && typeof call.name === "string") : [];
  } catch {
    return [];
  }
}

function stream(model: Model<Api>, context: TranscriptContext, options?: SimpleStreamOptions): AssistantMessageEventStream {
  const events = createAssistantMessageEventStream();
  (async () => {
    const output: AssistantMessage = {
      role: "assistant", content: [], api: model.api, provider: model.provider, model: model.id,
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      stopReason: "pending", timestamp: Date.now(),
    };
    try {
      const messages = context.messages as Array<{ role: string; content: unknown }>;
      const users = messages.filter((message) => message.role === "user");
      const prompt = textOf(users[0]?.content);
      const toolResults = messages.filter((message) => message.role === "toolResult").length;
      events.push({ type: "start", partial: output });
      // Names are sent whether or not Pi declared them: what Pi does with a call to a tool it
      // never declared is part of what the fixture checks.
      const calls = toolResults === 0 ? plannedCalls() : [];
      if (calls.length > 0) {
        calls.forEach((call, index) => {
          const toolCall = { type: "toolCall" as const, id: `synthetic-${Date.now()}-${index}`, name: call.name,
            arguments: call.arguments ?? {} };
          output.content.push(toolCall);
          const contentIndex = output.content.length - 1;
          events.push({ type: "toolcall_start", contentIndex, partial: output });
          events.push({ type: "toolcall_end", contentIndex, toolCall, partial: output });
        });
        output.stopReason = "toolUse";
      } else {
        const text = await finalText(prompt);
        output.content.push({ type: "text", text });
        const contentIndex = output.content.length - 1;
        events.push({ type: "text_start", contentIndex, partial: output });
        events.push({ type: "text_delta", contentIndex, delta: text, partial: output });
        events.push({ type: "text_end", contentIndex, content: text, partial: output });
        output.stopReason = "stop";
      }
      if (options?.signal?.aborted) throw new Error("Request was aborted");
      events.push({ type: "done", reason: output.stopReason as "stop" | "toolUse", message: output });
      events.end();
    } catch (error) {
      output.stopReason = options?.signal?.aborted ? "aborted" : "error";
      output.errorMessage = error instanceof Error ? error.message : String(error);
      events.push({ type: "error", reason: output.stopReason as "aborted" | "error", error: output });
      events.end();
    }
  })();
  return events;
}

export default function scanevalSyntheticProvider(pi: ExtensionAPI): void {
  pi.registerProvider(SYNTHETIC_PROVIDER, {
    name: "ScanEval synthetic (diagnostic, no model)",
    baseUrl: "http://synthetic.invalid",
    apiKey: "synthetic-not-a-credential",
    api: "scaneval-synthetic-api",
    models: [{
      id: SYNTHETIC_MODEL, name: "Deterministic open-context fixture", reasoning: true, input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 200_000, maxTokens: 32_000,
    }],
    streamSimple: stream,
  } as Parameters<ExtensionAPI["registerProvider"]>[1]);
}
