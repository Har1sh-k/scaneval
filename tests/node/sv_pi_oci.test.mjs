// Focused tests of the SV-Agent image route's Pi runner and research tools, run with Node's own
// test runner (Node strips the runner's TypeScript types itself). No Pi process and no model are
// involved: the runner gets a recording exec, and the tools run against a real Git repository and
// a local stand-in for the recorded retrieval API.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ADAPTERS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "scaneval", "adapters");
const runner = await import(join(ADAPTERS, "pi_oci_runner.mts"));
const tools = await import(join(ADAPTERS, "pi_open_context_tools.mjs"));

// The subset of TypeBox the tool definitions use, as plain JSON Schema.
const Type = {
  Object: (properties) => ({ type: "object", properties }),
  String: (options = {}) => ({ type: "string", ...options }),
  Integer: (options = {}) => ({ type: "integer", ...options }),
  Optional: (schema) => ({ ...schema, optional: true }),
  Literal: (value) => ({ const: value }),
  Union: (schemas) => ({ anyOf: schemas }),
};

const PROMPT = "SOURCE-BEARING PROMPT\n--model not-a-flag\nline three";
const STAGE = ["-p", "--no-session", "--model", "openai-codex/gpt-5.6-sol", "--thinking", "medium", PROMPT];

function piStream({ text = "answer", stopReason = "stop", errorMessage, tools: executed = [] } = {}) {
  const lines = [
    { type: "session", version: 3, id: "s", timestamp: "t", cwd: "/tmp" },
    { type: "message_end", message: { role: "user", content: PROMPT } },
    ...executed.map(([name, isError]) => ({ type: "tool_execution_end", toolCallId: "c", toolName: name, isError })),
    { type: "message_end", message: { role: "assistant", provider: "openai-codex", model: "gpt-5.6-sol",
      stopReason: "toolUse", content: [], usage: { input: 3, output: 1, cacheRead: 0, cacheWrite: 0, cost: { total: 0.25 } } } },
    { type: "message_end", message: { role: "assistant", provider: "openai-codex", model: "gpt-5.6-sol", stopReason,
      ...(errorMessage ? { errorMessage } : {}),
      content: [{ type: "thinking", thinking: "hidden" }, { type: "text", text }],
      usage: { input: 10, output: 5, cacheRead: 2, cacheWrite: 0, cost: { total: 0.5 } } } },
  ];
  return lines.map((line) => JSON.stringify(line)).join("\n") + "\n";
}

function makeRunner(overrides = {}) {
  const calls = [];
  const observations = [];
  const raw = runner.createPiOciRawRunner({
    exec: async (command, args, options) => {
      calls.push({ command, args, options });
      return overrides.result ?? { code: 0, stdout: piStream(), stderr: "" };
    },
    piBinary: "pi", provider: "openai-codex", modelId: "gpt-5.6-sol", requestedModel: "openai-codex/gpt-5.6-sol",
    thinkingLevel: "high", agentDir: "/tmp/agent", extensions: ["/opt/scaneval/pi_open_context.mts"],
    tools: ["scaneval_fetch", "scaneval_git", "scaneval_read"],
    environment: { PATH: "/usr/bin", HTTPS_PROXY: "http://proxy:3128" },
    sessionRoot: "/raw/pi-sessions",
    onCall: (observation) => observations.push(observation),
    ...overrides.options,
  });
  return { raw, calls, observations };
}

test("the prompt travels on stdin and the argv is the explicit tool policy, nothing from the stage", async () => {
  const { raw, calls, observations } = makeRunner();
  const result = await raw.runPi({ args: STAGE, cwd: "/tmp/iso", timeoutMs: 1000,
    env: { OPENAI_API_KEY: "sk-must-not-pass", SV_AGENT_PI_AUTH_JSON: "{}" } });
  assert.equal(calls.length, 1);
  const { command, args, options } = calls[0];
  assert.equal(command, "pi");
  assert.deepEqual(args, ["--mode", "json", "--provider", "openai-codex", "--model", "gpt-5.6-sol", "--thinking", "high",
    "--no-extensions", "-e", "/opt/scaneval/pi_open_context.mts", "--tools", "scaneval_fetch,scaneval_git,scaneval_read",
    "--no-mcp", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve", "--no-session"]);
  assert.ok(!args.includes("--no-tools"));
  assert.ok(!args.some((word) => word.includes("SOURCE-BEARING")));
  assert.equal(options.stdin, PROMPT);
  assert.equal(options.cwd, "/tmp/iso");
  assert.deepEqual(options.env, { PATH: "/usr/bin", HTTPS_PROXY: "http://proxy:3128", PI_CODING_AGENT_DIR: "/tmp/agent" });
  // What --print would have printed: each text block of the last assistant message and a newline.
  assert.deepEqual({ code: result.code, stdout: result.stdout, stderr: result.stderr }, { code: 0, stdout: "answer\n", stderr: "" });
  assert.equal(observations[0].thinking_requested_by_stage, "medium");
  assert.equal(observations[0].thinking_applied, "high");
  assert.equal(observations[0].model_addressed, "gpt-5.6-sol");
  assert.deepEqual(observations[0].usage, { input: 13, output: 6, cacheRead: 2, cacheWrite: 0, cost: 0.75 });
});

test("an error, abort or length stop is reported the way print mode reports it", async () => {
  for (const [stopReason, expected] of [["error", 1], ["aborted", 1], ["length", 1]]) {
    const { raw } = makeRunner({ result: { code: 0, stdout: piStream({ stopReason, errorMessage: "upstream said no" }), stderr: "" } });
    const result = await raw.runPi({ args: STAGE, cwd: "/tmp", timeoutMs: 1000 });
    assert.equal(result.code, expected, stopReason);
    if (stopReason === "length") {
      assert.equal(result.stdout, "answer\n");
      assert.match(result.stderr, /output token limit/);
    } else {
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /upstream said no/);
    }
  }
  const { raw } = makeRunner({ result: { code: 0, stdout: "", stderr: "" } });
  const empty = await raw.runPi({ args: STAGE, cwd: "/tmp", timeoutMs: 1000 });
  assert.equal(empty.code, 1);
});

test("unsupported stage argv fails without quoting prompt text, and another model route is refused", async () => {
  const { raw, calls } = makeRunner();
  await assert.rejects(raw.runPi({ args: ["-p", "--append-system-prompt", "x", PROMPT], cwd: "/tmp", timeoutMs: 1 }),
    (error) => /does not support: --append-system-prompt/.test(error.message) && !error.message.includes("SOURCE"));
  await assert.rejects(raw.runPi({ args: ["-p", "SECRET-POSITIONAL", PROMPT], cwd: "/tmp", timeoutMs: 1 }),
    (error) => !error.message.includes("SECRET-POSITIONAL"));
  await assert.rejects(raw.runPi({ args: ["-p", "--model", "anthropic/claude", PROMPT], cwd: "/tmp", timeoutMs: 1 }),
    /pins openai-codex\/gpt-5.6-sol; no other route/);
  await assert.rejects(raw.runPi({ args: ["--model", "openai-codex/gpt-5.6-sol", PROMPT], cwd: "/tmp", timeoutMs: 1 }),
    /print mode/);
  assert.equal(calls.length, 0);
});

test("stage --no-tools is replaced by the explicit allowlist and reported, and sessions stay inside the root", async () => {
  const { raw, calls, observations } = makeRunner();
  await raw.runPi({ args: ["-p", "--no-tools", "--no-extensions", "--model", "openai-codex/gpt-5.6-sol", PROMPT],
    cwd: "/tmp", timeoutMs: 1, env: { PI_CODING_AGENT_SESSION_DIR: "/raw/pi-sessions/call-1" } });
  assert.deepEqual(observations[0].replaced_stage_flags, ["--no-tools", "--no-extensions"]);
  assert.equal(calls[0].options.env.PI_CODING_AGENT_SESSION_DIR, "/raw/pi-sessions/call-1");
  assert.ok(!calls[0].args.includes("--no-session"));
  await assert.rejects(raw.runPi({ args: ["-p", "--model", "openai-codex/gpt-5.6-sol", PROMPT], cwd: "/tmp", timeoutMs: 1,
    env: { PI_CODING_AGENT_SESSION_DIR: "/home/user/.pi/sessions" } }), /outside the run's session root/);
});

test("the runner refuses an unknown thinking level and a stage output over its own bound", async () => {
  assert.throws(() => makeRunner({ options: { thinkingLevel: "ultra" } }), /not one Pi accepts/);
  const { raw } = makeRunner({ result: { code: 0, stdout: piStream({ text: "x".repeat(100) }), stderr: "" } });
  await assert.rejects(raw.runPi({ args: STAGE, cwd: "/tmp", timeoutMs: 1, maxOutputBytes: 10 }), /byte limit/);
});

function gitRepository() {
  const root = mkdtempSync(join(tmpdir(), "sv-oc-repo-"));
  const git = (...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false", ...args],
    { cwd: root, env: { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" } });
  git("init", "-q");
  writeFileSync(join(root, "app.py"), "def handler():\n    return 'v1'\n");
  git("add", "app.py");
  git("commit", "-q", "-m", "first ancestor");
  writeFileSync(join(root, "app.py"), "def handler():\n    return 'v2'\n");
  git("commit", "-q", "-am", "second ancestor");
  return root;
}

test("history tools are fixed read-only operations rooted at the repository, not the working directory", async () => {
  const repo = gitRepository();
  const journal = mkdtempSync(join(tmpdir(), "sv-oc-journal-"));
  const outside = mkdtempSync(join(tmpdir(), "sv-oc-outside-"));
  writeFileSync(join(outside, "secret.txt"), "OUTSIDE-SECRET");
  symlinkSync(join(outside, "secret.txt"), join(repo, "escape.txt"));
  const { tools: defined } = tools.createOpenContextTools({ Type, env: { SCANEVAL_OPEN_CONTEXT_REPO: repo,
    SCANEVAL_OPEN_CONTEXT_JOURNAL: journal, PATH: process.env.PATH } });
  assert.deepEqual(defined.map((tool) => tool.name), ["scaneval_git", "scaneval_read"]);
  const git = defined.find((tool) => tool.name === "scaneval_git");
  const read = defined.find((tool) => tool.name === "scaneval_read");
  const log = await git.execute("1", { op: "log" });
  assert.match(log.content[0].text, /second ancestor/);
  assert.match(log.content[0].text, /first ancestor/);
  const file = await git.execute("2", { op: "file", rev: "HEAD~1", path: "app.py" });
  assert.match(file.content[0].text, /'v1'/);
  for (const params of [{ op: "log", rev: "--output=/tmp/x" }, { op: "log", rev: "HEAD..HEAD~1" },
    { op: "show", path: "../etc/passwd" }, { op: "file", path: "-c" }, { op: "grep", pattern: "a\nb" },
    { op: "rm" }, { op: "log", path: ":(glob)*" }]) {
    await assert.rejects(git.execute("x", params), Error, JSON.stringify(params));
  }
  const source = await read.execute("3", { path: "app.py" });
  assert.match(source.content[0].text, /1\tdef handler/);
  await assert.rejects(read.execute("4", { path: "escape.txt" }), /outside the repository root/);
  await assert.rejects(read.execute("5", { path: ".git/config" }), /scaneval_git/);
  const lines = readdirSync(journal).flatMap((name) => readFileSync(join(journal, name), "utf8").trim().split("\n"))
    .map((line) => JSON.parse(line));
  assert.equal(lines[0].event, "loaded");
  assert.deepEqual(lines[0].tools, ["scaneval_git", "scaneval_read"]);
  const text = JSON.stringify(lines);
  assert.ok(!text.includes("'v1'") && !text.includes("OUTSIDE-SECRET"), "the journal holds metadata, never content");
});

test("fetch reaches the recorded API directly, never through the inference proxy, and a denial fails the tool", async () => {
  const seen = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const payload = JSON.parse(body);
      seen.push({ path: request.url, payload });
      const denied = String(payload.url ?? "").includes("127.0.0.1");
      const reply = denied
        ? { id: "e2", outcome: "denied", url: payload.url, error: "destination has no public address", redirect_chain: [] }
        : { id: "e1", outcome: "ok", url: payload.url ?? null, query: payload.query ?? null, content_sha256: "sha256:abc",
          byte_count: 5, capture_status: "preserved", redirect_chain: [{ status: 200 }],
          content_base64: Buffer.from("hello").toString("base64") };
      response.writeHead(denied ? 403 : 200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(reply));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const repo = gitRepository();
  const journal = mkdtempSync(join(tmpdir(), "sv-oc-journal-"));
  // A dead proxy in the environment: a client that honoured it could not reach the API at all.
  const saved = { ...process.env };
  Object.assign(process.env, { HTTP_PROXY: "http://127.0.0.1:9", http_proxy: "http://127.0.0.1:9", NO_PROXY: "", no_proxy: "" });
  try {
    const { tools: defined } = tools.createOpenContextTools({ Type, env: { SCANEVAL_OPEN_CONTEXT_REPO: repo,
      SCANEVAL_RETRIEVAL_URL: `http://127.0.0.1:${port}`, SCANEVAL_OPEN_CONTEXT_SEARCH: "1",
      SCANEVAL_OPEN_CONTEXT_JOURNAL: journal } });
    assert.deepEqual(defined.map((tool) => tool.name), ["scaneval_fetch", "scaneval_search", "scaneval_git", "scaneval_read"]);
    const fetchTool = defined.find((tool) => tool.name === "scaneval_fetch");
    const searchTool = defined.find((tool) => tool.name === "scaneval_search");
    const fetched = await fetchTool.execute("1", { url: "https://example.com/advisory" });
    assert.match(fetched.content[0].text, /fetch outcome: ok/);
    assert.match(fetched.content[0].text, /hello/);
    await assert.rejects(fetchTool.execute("2", { url: "https://127.0.0.1/metadata" }), /retrieval denied/);
    await searchTool.execute("3", { query: "CVE advisory" });
    assert.deepEqual(seen.map((entry) => [entry.path, entry.payload.source]),
      [["/fetch", "browser_tool"], ["/fetch", "browser_tool"], ["/search", "browser_tool"]]);
    const records = readdirSync(journal).flatMap((name) => readFileSync(join(journal, name), "utf8").trim().split("\n"))
      .map((line) => JSON.parse(line)).filter((record) => record.event === "tool");
    assert.deepEqual(records.map((record) => [record.tool, record.outcome, record.retrieval_event_id]),
      [["scaneval_fetch", "returned", "e1"], ["scaneval_fetch", "refused", "e2"], ["scaneval_search", "returned", "e1"]]);
    assert.ok(!JSON.stringify(records).includes("hello"));
  } finally {
    for (const key of ["HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"]) {
      if (key in saved) process.env[key] = saved[key]; else delete process.env[key];
    }
    server.close();
  }
});

test("a malformed retrieval endpoint or repository root is refused before any tool exists", () => {
  const repo = gitRepository();
  assert.throws(() => tools.loadSettings({ SCANEVAL_OPEN_CONTEXT_REPO: "relative" }), /absolute repository root/);
  assert.throws(() => tools.loadSettings({ SCANEVAL_OPEN_CONTEXT_REPO: repo, SCANEVAL_RETRIEVAL_URL: "https://x:1" }),
    /plain http/);
  assert.throws(() => tools.loadSettings({ SCANEVAL_OPEN_CONTEXT_REPO: repo, SCANEVAL_RETRIEVAL_URL: "http://u:p@x:1" }),
    /plain http/);
  mkdirSync(join(repo, "sub"));
  assert.equal(tools.loadSettings({ SCANEVAL_OPEN_CONTEXT_REPO: repo }).retrieval, null);
});

// Optional installed-Pi check, with fabricated credentials and no transport. The ordinary
// runner tests above need no Pi installation. Set SCANEVAL_PI_PACKAGE_ROOT to the pinned 1.4.0
// package to exercise its real OAuth resolver and Codex auth derivation, never its CLI/login.
test("Pi 1.4.0 resolves the access-only sentinel without attempting refresh", {
  skip: !process.env.SCANEVAL_PI_PACKAGE_ROOT,
}, async () => {
  const root = process.env.SCANEVAL_PI_PACKAGE_ROOT;
  assert.equal(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version, "1.4.0");
  const ai = join(root, "node_modules", "@earendil-works", "pi-ai", "dist");
  const { resolveProviderAuth } = await import(join(ai, "auth", "resolve.js"));
  const { openaiCodexOAuth } = await import(join(ai, "auth", "oauth", "openai-codex.js"));
  let reads = 0;
  let modifications = 0;
  const fakeAccess = "fabricated-access-no-network";
  const credentials = {
    async read() {
      reads++;
      return { type: "oauth", access: fakeAccess, refresh: "scaneval-refresh-disabled",
        expires: Date.now() + (1800 + 300 + 60) * 1000, accountId: "fabricated-account" };
    },
    async modify() { modifications++; throw new Error("unexpected refresh attempt"); },
  };
  const resolved = await resolveProviderAuth({ id: "openai-codex", auth: { oauth: openaiCodexOAuth } },
    credentials, { async env() { throw new Error("unexpected ambient credential access"); } });
  assert.deepEqual(resolved, { auth: { apiKey: fakeAccess }, source: "OAuth" });
  assert.equal(reads, 1);
  assert.equal(modifications, 0);
});
