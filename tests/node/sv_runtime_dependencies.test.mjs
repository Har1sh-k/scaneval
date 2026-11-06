// Real installed Pi and dependency checks. No model or external service is called.
// Install containers/sv-agent with npm ci --omit=dev --ignore-scripts --engine-strict first.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import { createRequire, registerHooks } from "node:module";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const RUNTIME = join(ROOT, "containers", "sv-agent");
const PI = join(RUNTIME, "node_modules", "@earendil-works", "pi-coding-agent");
const ADAPTERS = join(ROOT, "src", "scaneval", "adapters");
const requireRuntime = createRequire(join(RUNTIME, "package.json"));
const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const bundled = (url) => /\/@earendil-works\/pi-[^/]+\/dist\/bundle\//.test(url);
registerHooks({
  resolve(specifier, context, nextResolve) {
    const result = nextResolve(specifier, context);
    assert.equal(bundled(result.url), false, `unexpected prebuilt bundle: ${result.url}`);
    return result;
  },
});

test("real Pi SDK and model globs use the patched installed dependencies", async () => {
  assert.equal(json(join(PI, "package.json")).version, "1.4.0");
  assert.equal(json(join(RUNTIME, "node_modules", "minimatch", "package.json")).version, "11.0.3");
  assert.equal(json(join(RUNTIME, "node_modules", "undici", "package.json")).version, "8.12.4");
  const pi = await import(pathToFileURL(join(PI, "dist", "index.js")).href);
  for (const name of ["createAgentSession", "DefaultPackageManager", "createReadTool"]) {
    assert.equal(typeof pi[name], "function", name);
  }
  const models = [
    { provider: "openai-codex", id: "gpt-5.4", name: "GPT5.4" },
    { provider: "anthropic", id: "claude-sonnet-4", name: "Claude Sonnet4" },
    { provider: "openai-codex", id: "other", name: "Other" },
  ];
  const result = await pi.resolveModelScopeWithDiagnostics(
    ["OPENAI-CODEX/GPT-5.*:high", "*sonnet*"], { getAvailable: async () => models },
  );
  assert.deepEqual(result.diagnostics, []);
  assert.deepEqual(result.scopedModels.map((row) => [row.model.id, row.thinkingLevel]),
    [["gpt-5.4", "high"], ["claude-sonnet-4", undefined]]);
  const { minimatch } = await import(pathToFileURL(requireRuntime.resolve("minimatch")).href);
  assert.equal(minimatch("src/lib/foo1.ts", "**/{foo,bar}?.ts"), true);
  assert.equal(minimatch("src/lib/foo1.js", "**/{foo,bar}?.ts"), false);
});

test("image launcher runs real unbundled Pi and research extensions without a bundle fallback", () => {
  const scratch = mkdtempSync(join(tmpdir(), "scaneval-runtime-smoke-"));
  try {
    // Reproduce the launcher's image-relative layout with the real installed package tree.
    copyFileSync(join(RUNTIME, "pi-cli.mjs"), join(scratch, "pi-cli.mjs"));
    symlinkSync(join(RUNTIME, "node_modules"), join(scratch, "node_modules"), "dir");
    mkdirSync(join(scratch, "source"));
    writeFileSync(join(scratch, "source", "fixture.txt"), "synthetic source marker\n");
    const hook = join(scratch, "no-bundle.mjs");
    const resolutions = join(scratch, "resolutions.jsonl");
    writeFileSync(hook, `import { registerHooks } from "node:module";
import { appendFileSync } from "node:fs";
registerHooks({resolve(specifier,context,nextResolve){
 const result=nextResolve(specifier,context);
 if (/\\/@earendil-works\\/pi-[^/]+\\/dist\\/bundle\\//.test(result.url))
   throw new Error("prebuilt Pi bundle was selected: "+result.url);
 if (["minimatch","undici"].includes(specifier))
   appendFileSync(${JSON.stringify(resolutions)},JSON.stringify({specifier,url:result.url})+"\\n");
 return result;
}});
`);
    const env = {
      PATH: process.env.PATH, HOME: scratch, TMPDIR: scratch,
      PI_CODING_AGENT_DIR: join(scratch, "agent"), PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", PI_TELEMETRY: "0",
      SCANEVAL_OPEN_CONTEXT_REPO: join(scratch, "source"),
      SCANEVAL_SYNTHETIC_TOOL_CALLS: JSON.stringify([{ name: "scaneval_read", arguments: { path: "fixture.txt" } }]),
    };
    const run = (args, input) => execFileSync(process.execPath,
      ["--import", pathToFileURL(hook).href, join(scratch, "pi-cli.mjs"), ...args],
      { cwd: scratch, env, input, encoding: "utf8", timeout: 30_000 });
    assert.equal(run(["--version"]).trim(), "1.4.0");
    const stream = run([
      "--mode", "json", "--provider", "scaneval-synthetic", "--model", "deterministic-open-context",
      "--thinking", "off", "--no-extensions", "-e", join(ADAPTERS, "pi_open_context.mts"),
      "-e", join(ADAPTERS, "pi_synthetic_provider.mts"), "--tools", "scaneval_read",
      "--no-mcp", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files",
      "--no-approve", "--no-session",
    ], "Run the synthetic diagnostic.\n");
    const events = stream.trim().split("\n").map((line) => JSON.parse(line));
    const tool = events.find((event) => event.type === "tool_execution_end" && event.toolName === "scaneval_read");
    assert.ok(tool, "the real Pi process did not execute the research extension's read tool");
    assert.equal(tool.isError, false);
    assert.match(JSON.stringify(tool.result), /synthetic source marker/);
    const messages = events.filter((event) => event.type === "message_end" && event.message.role === "assistant");
    assert.equal(messages.at(-1).message.stopReason, "stop");
    assert.equal(messages.at(-1).message.provider, "scaneval-synthetic");
    const imports = readFileSync(resolutions, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    for (const name of ["minimatch", "undici"]) {
      assert.ok(imports.some((row) => row.specifier === name && row.url.includes(`/node_modules/${name}/`)),
        `the executed CLI did not resolve the patched ${name} package`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("real Pi HTTP dispatcher uses CONNECT and respects NO_PROXY with patched undici", async () => {
  const undici = await import(pathToFileURL(requireRuntime.resolve("undici")).href);
  const { configureHttpDispatcher } = await import(pathToFileURL(join(PI, "dist/core/http-dispatcher.js")).href);
  const savedDispatcher = undici.getGlobalDispatcher();
  const savedFetch = globalThis.fetch;
  const envNames = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"];
  const savedEnv = Object.fromEntries(envNames.map((name) => [name, process.env[name]]));
  const sockets = new Set();
  const origin = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify({ path: req.url }));
  });
  const proxy = http.createServer((_req, res) => { res.writeHead(500); res.end("CONNECT required"); });
  for (const server of [origin, proxy]) server.on("connection", (socket) => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket));
  });
  let tunnels = 0;
  proxy.on("connect", (req, client, head) => {
    const [host, port] = req.url.split(":");
    assert.equal(host, "127.0.0.1"); assert.equal(Number(port), origin.address().port);
    tunnels += 1;
    const upstream = net.connect(Number(port), host, () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      client.pipe(upstream); upstream.pipe(client);
    });
    upstream.on("error", () => client.destroy()); client.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
  });
  try {
    origin.listen(0, "127.0.0.1"); await once(origin, "listening");
    proxy.listen(0, "127.0.0.1"); await once(proxy, "listening");
    process.env.HTTP_PROXY = process.env.HTTPS_PROXY = `http://127.0.0.1:${proxy.address().port}`;
    process.env.NO_PROXY = "";
    for (const name of ["http_proxy", "https_proxy", "no_proxy"]) delete process.env[name];
    configureHttpDispatcher(2000);
    const first = await fetch(`http://127.0.0.1:${origin.address().port}/proxy`);
    assert.deepEqual(await first.json(), { path: "/proxy" }); assert.equal(tunnels, 1);
    await undici.getGlobalDispatcher().close();
    process.env.NO_PROXY = "127.0.0.1";
    configureHttpDispatcher(2000);
    const second = await fetch(`http://127.0.0.1:${origin.address().port}/direct`);
    assert.deepEqual(await second.json(), { path: "/direct" }); assert.equal(tunnels, 1);
  } finally {
    await undici.getGlobalDispatcher().close();
    undici.setGlobalDispatcher(savedDispatcher); globalThis.fetch = savedFetch;
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    for (const socket of sockets) socket.destroy();
    origin.close(); proxy.close();
  }
});
