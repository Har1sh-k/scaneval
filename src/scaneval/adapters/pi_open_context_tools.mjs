// Research and history tools for the SV-Agent open-context Pi route.
//
// Loaded inside the Pi process by pi_open_context.mts, which only wraps these definitions with
// Pi's own defineTool. Everything that decides what a tool may touch lives here, in plain
// JavaScript with no Pi import, so it can be exercised by itself.
//
// Four tools, each bounded and none able to run arbitrary code:
//
//   * scaneval_fetch  -- one public HTTPS GET through the recorded retrieval API
//                        ($SCANEVAL_RETRIEVAL_URL/fetch). The proxy decides what is allowed and
//                        records every attempt; this client never talks to the internet itself.
//   * scaneval_search -- the same API's /search, registered only when the run declares a search
//                        endpoint.
//   * scaneval_git    -- fixed read-only history operations against the explicit repository root
//                        the driver names, never the per-call temporary working directory.
//   * scaneval_read   -- a bounded read or listing of the exported source under that same root.
//
// The journal written here is the extension's own account of what it registered and what each
// tool call returned. It is tool availability and tool execution evidence; it is not evidence
// that the model read, used, or relied on anything a tool returned.

import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync, closeSync, constants, fstatSync, openSync, readSync, readdirSync, realpathSync,
} from "node:fs";
import http from "node:http";
import { isAbsolute, join, relative, sep } from "node:path";

export const OPEN_CONTEXT_TOOLS_VERSION = "1.0.0";
export const TOOL_NAMES = Object.freeze({
  fetch: "scaneval_fetch", search: "scaneval_search", git: "scaneval_git", read: "scaneval_read",
});
export const GIT_OPERATIONS = Object.freeze(["log", "show", "file", "blame", "grep"]);

const MAX_MODEL_TEXT = 100_000;
const MAX_RETRIEVAL_REPLY_BYTES = 4 * 1024 * 1024;
const MAX_RETRIEVAL_REQUEST_BYTES = 16_000;
const RETRIEVAL_TIMEOUT_MS = 90_000;
const GIT_TIMEOUT_MS = 20_000;
const GIT_MAX_BUFFER = 2 * 1024 * 1024;
const MAX_GIT_TEXT = 200_000;
const MAX_READ_BYTES = 256 * 1024;
const MAX_LIST_ENTRIES = 1_000;
const MAX_JOURNAL_TEXT = 2_048;
// HEAD, or an abbreviated or full object id, each optionally followed by ancestry steps. Nothing
// here can name a ref outside the bounded history, start an option, or carry a range.
const REVISION = /^(?:HEAD|[0-9a-fA-F]{4,64})(?:[~^][0-9]{0,4})*$/;

function clip(text, limit) {
  return text.length > limit ? `${text.slice(0, limit)}\n[truncated: ${text.length - limit} more characters]` : text;
}

function journalValue(value) {
  return typeof value === "string" ? value.slice(0, MAX_JOURNAL_TEXT) : value;
}

/** What the extension was configured with, read from the environment the runner built. */
export function loadSettings(env) {
  const repo = env.SCANEVAL_OPEN_CONTEXT_REPO;
  if (typeof repo !== "string" || !isAbsolute(repo) || repo.includes("\0")) {
    throw new Error("SCANEVAL_OPEN_CONTEXT_REPO must name the absolute repository root");
  }
  let repoReal;
  try {
    repoReal = realpathSync(repo);
  } catch {
    throw new Error("SCANEVAL_OPEN_CONTEXT_REPO does not resolve to a directory");
  }
  let retrieval = null;
  const raw = env.SCANEVAL_RETRIEVAL_URL;
  if (typeof raw === "string" && raw) {
    const parsed = new URL(raw);
    if (parsed.protocol !== "http:" || !parsed.hostname || parsed.username || parsed.password
        || (parsed.pathname !== "/" && parsed.pathname !== "")) {
      throw new Error("SCANEVAL_RETRIEVAL_URL must be the plain http://host:port of the recorded retrieval API");
    }
    retrieval = parsed;
  }
  const journalDir = typeof env.SCANEVAL_OPEN_CONTEXT_JOURNAL === "string" && isAbsolute(env.SCANEVAL_OPEN_CONTEXT_JOURNAL)
    ? env.SCANEVAL_OPEN_CONTEXT_JOURNAL : null;
  return {
    repo: repoReal,
    retrieval,
    search: env.SCANEVAL_OPEN_CONTEXT_SEARCH === "1",
    journalDir,
    git: typeof env.SCANEVAL_OPEN_CONTEXT_GIT === "string" && env.SCANEVAL_OPEN_CONTEXT_GIT
      ? env.SCANEVAL_OPEN_CONTEXT_GIT : "git",
  };
}

/** One append-only JSONL file per Pi process; a failed write is counted, never thrown. */
export function createJournal(directory) {
  const state = { path: null, failures: 0 };
  if (directory) state.path = join(directory, `pi-${process.pid}-${randomBytes(6).toString("hex")}.jsonl`);
  return {
    state,
    write(record) {
      if (!state.path) return;
      try {
        appendFileSync(state.path, `${JSON.stringify({ schema: "scaneval.open_context_tool/1",
          ts: new Date().toISOString(), ...record })}\n`, { mode: 0o644, flag: "a" });
      } catch {
        state.failures += 1;
      }
    },
  };
}

function checkRelativePath(value, { allowEmpty = false } = {}) {
  if (value === undefined || value === null || value === "" || value === ".") {
    if (allowEmpty) return "";
    throw new Error("a repository-relative path is required");
  }
  if (typeof value !== "string" || value.length > 1024 || value.includes("\0") || value.includes("\\")) {
    throw new Error("path must be a repository-relative POSIX path of at most 1024 characters");
  }
  const trimmed = value.startsWith("./") ? value.slice(2) : value;
  if (isAbsolute(trimmed) || trimmed.startsWith("-") || trimmed.startsWith(":")) {
    throw new Error("path must be relative to the repository root and must not start with '-' or ':'");
  }
  const parts = trimmed.split("/").filter((part) => part !== "" && part !== ".");
  if (parts.some((part) => part === "..")) throw new Error("path must not leave the repository root");
  return parts.join("/");
}

function checkRevision(value, fallback) {
  const revision = value === undefined || value === null || value === "" ? fallback : value;
  if (typeof revision !== "string" || !REVISION.test(revision)) {
    throw new Error("rev must be HEAD or a commit id, optionally followed by ~N or ^N");
  }
  return revision;
}

function boundedInteger(value, fallback, minimum, maximum, name) {
  if (value === undefined || value === null) return fallback;
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

/** The argv of one fixed history operation; every user value has been checked before it is placed. */
export function gitArguments(repo, params) {
  const op = params?.op;
  if (!GIT_OPERATIONS.includes(op)) throw new Error(`op must be one of ${GIT_OPERATIONS.join(", ")}`);
  const prefix = ["--no-pager", "-c", `safe.directory=${repo}`, "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "--git-dir", join(repo, ".git"), "--work-tree", repo];
  switch (op) {
    case "log": {
      const path = checkRelativePath(params.path, { allowEmpty: true });
      const count = boundedInteger(params.max_count, 20, 1, 100, "max_count");
      return [...prefix, "log", "--no-color", "--no-decorate", "--date=iso-strict",
        "--format=%H%x09%ad%x09%an%x09%s", `--max-count=${count}`, checkRevision(params.rev, "HEAD"),
        "--", ...(path ? [path] : [])];
    }
    case "show": {
      const path = checkRelativePath(params.path, { allowEmpty: true });
      return [...prefix, "show", "--no-color", "--no-ext-diff", "--no-textconv", "--stat", "--patch",
        checkRevision(params.rev, "HEAD"), "--", ...(path ? [path] : [])];
    }
    case "file":
      return [...prefix, "show", "--no-color", "--no-textconv",
        `${checkRevision(params.rev, "HEAD")}:${checkRelativePath(params.path)}`];
    case "blame": {
      const path = checkRelativePath(params.path);
      const start = boundedInteger(params.start_line, undefined, 1, 10_000_000, "start_line");
      const end = boundedInteger(params.end_line, undefined, 1, 10_000_000, "end_line");
      if ((start === undefined) !== (end === undefined) || (start !== undefined && end < start)) {
        throw new Error("blame takes both start_line and end_line, with end_line >= start_line, or neither");
      }
      return [...prefix, "blame", "-w", ...(start !== undefined ? ["-L", `${start},${end}`] : []),
        checkRevision(params.rev, "HEAD"), "--", path];
    }
    case "grep": {
      const pattern = params.pattern;
      if (typeof pattern !== "string" || !pattern || pattern.length > 512 || /[\0\n\r]/.test(pattern)) {
        throw new Error("grep needs a fixed-string pattern of 1 to 512 characters on one line");
      }
      const path = checkRelativePath(params.path, { allowEmpty: true });
      return [...prefix, "grep", "-n", "-I", "-F", "--no-color", "-e", pattern, checkRevision(params.rev, "HEAD"),
        "--", ...(path ? [path] : [])];
    }
  }
  throw new Error("unreachable git operation");
}

/** The environment of every history command: no user or system configuration, no prompts. */
export function gitEnvironment(env) {
  return {
    PATH: env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: env.HOME ?? "/tmp",
    LANG: "C", LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0",
    GIT_NO_REPLACE_OBJECTS: "1", GIT_LITERAL_PATHSPECS: "1", GIT_PAGER: "cat", PAGER: "cat",
  };
}

function runGit(settings, args, env, signal) {
  return new Promise((resolve) => {
    execFile(settings.git, args, { cwd: settings.repo, env: gitEnvironment(env), timeout: GIT_TIMEOUT_MS,
      maxBuffer: GIT_MAX_BUFFER, encoding: "buffer", signal, windowsHide: true },
    (error, stdout, stderr) => {
      const out = Buffer.isBuffer(stdout) ? stdout : Buffer.alloc(0);
      const err = Buffer.isBuffer(stderr) ? stderr : Buffer.alloc(0);
      const code = error ? (typeof error.code === "number" ? error.code : null) : 0;
      resolve({ code, stdout: out, stderr: err, failure: error && typeof error.code !== "number" ? String(error.code ?? error.name) : null });
    });
  });
}

/** POST one request to the recorded retrieval API, bypassing every proxy setting by construction. */
export function postRetrieval(base, route, payload, signal) {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  if (body.length > MAX_RETRIEVAL_REQUEST_BYTES) {
    return Promise.reject(new Error("retrieval request exceeds the API's request size limit"));
  }
  return new Promise((resolve, reject) => {
    // A private agent with no proxy configuration: the API sits on the scan network beside the
    // egress proxy and is reached directly, never through the inference proxy.
    const agent = new http.Agent({ keepAlive: false });
    const request = http.request({
      host: base.hostname, port: base.port || 80, path: route, method: "POST", agent,
      headers: { "Content-Type": "application/json", "Content-Length": String(body.length) },
      ...(signal ? { signal } : {}),
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_RETRIEVAL_REPLY_BYTES) {
          response.destroy(new Error("retrieval reply exceeds its size limit"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("error", reject);
      response.on("end", () => {
        try {
          resolve({ status: response.statusCode ?? 0, reply: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch {
          reject(new Error("the retrieval API returned a reply that is not JSON"));
        }
      });
    });
    request.setTimeout(RETRIEVAL_TIMEOUT_MS, () => request.destroy(new Error("retrieval request timed out")));
    request.on("error", (error) => { agent.destroy(); reject(error); });
    request.on("close", () => agent.destroy());
    request.end(body);
  });
}

function lastHopStatus(reply) {
  const chain = Array.isArray(reply?.redirect_chain) ? reply.redirect_chain : [];
  const last = chain[chain.length - 1];
  return typeof last?.status === "number" ? last.status : null;
}

function retrievalText(kind, reply) {
  let content = "";
  if (typeof reply.content_base64 === "string") {
    content = Buffer.from(reply.content_base64, "base64").toString("utf8");
  }
  const lines = [
    `${kind} outcome: ${reply.outcome}`,
    `url: ${reply.url ?? "unknown"}`,
    `http_status: ${lastHopStatus(reply) ?? "none"}`,
    `content_sha256: ${reply.content_sha256 ?? "none"}`,
    `bytes: ${typeof reply.byte_count === "number" ? reply.byte_count : 0}`,
    `retrieval_event_id: ${reply.id ?? "unknown"}`,
  ];
  if (reply.error) lines.push(`error: ${String(reply.error).slice(0, 500)}`);
  return `${lines.join("\n")}\n--- content (UTF-8, at most ${MAX_MODEL_TEXT} characters) ---\n${clip(content, MAX_MODEL_TEXT)}`;
}

function retrievalJournal(reply) {
  return {
    retrieval_event_id: journalValue(reply?.id ?? null), retrieval_outcome: reply?.outcome ?? null,
    http_status: lastHopStatus(reply), content_sha256: reply?.content_sha256 ?? null,
    byte_count: typeof reply?.byte_count === "number" ? reply.byte_count : null,
    capture_status: reply?.capture_status ?? null,
  };
}

function readSource(settings, params) {
  const op = params?.op ?? "file";
  if (op !== "file" && op !== "list") throw new Error("op must be file or list");
  const relativePath = checkRelativePath(params?.path, { allowEmpty: op === "list" });
  if (relativePath.split("/")[0] === ".git") throw new Error("use scaneval_git for repository history");
  let resolved;
  try {
    resolved = realpathSync(join(settings.repo, relativePath));
  } catch {
    throw new Error(`no such path in the repository: ${relativePath || "."}`);
  }
  const inside = relative(settings.repo, resolved);
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
    throw new Error("path resolves outside the repository root");
  }
  if (op === "list") {
    const entries = readdirSync(resolved, { withFileTypes: true })
      .map((entry) => `${entry.isDirectory() ? "d" : entry.isSymbolicLink() ? "l" : entry.isFile() ? "f" : "?"} ${entry.name}`)
      .sort();
    const shown = entries.slice(0, MAX_LIST_ENTRIES);
    return { text: shown.join("\n") + (entries.length > shown.length ? `\n[${entries.length - shown.length} more entries]` : ""),
      details: { path: relativePath, entries: entries.length } };
  }
  const descriptor = openSync(resolved, constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
  try {
    const status = fstatSync(descriptor);
    if (!status.isFile()) throw new Error("path is not a regular file");
    const buffer = Buffer.alloc(Math.min(status.size, MAX_READ_BYTES));
    const read = readSync(descriptor, buffer, 0, buffer.length, 0);
    let text = buffer.subarray(0, read).toString("utf8");
    const startLine = boundedInteger(params?.start_line, 1, 1, 10_000_000, "start_line");
    const maxLines = boundedInteger(params?.max_lines, 2_000, 1, 20_000, "max_lines");
    const lines = text.split("\n");
    text = lines.slice(startLine - 1, startLine - 1 + maxLines)
      .map((line, index) => `${startLine + index}\t${line}`).join("\n");
    const truncated = status.size > read;
    return { text: clip(text, MAX_MODEL_TEXT) + (truncated ? `\n[file truncated at ${MAX_READ_BYTES} bytes of ${status.size}]` : ""),
      details: { path: relativePath, bytes: read, size: status.size } };
  } finally {
    closeSync(descriptor);
  }
}

function textResult(text, details) {
  return { content: [{ type: "text", text }], details };
}

/**
 * The tool definitions this run registers, ready for Pi's defineTool.
 *
 * `Type` is Pi's TypeBox export; it is passed in so this module needs no Pi import.
 */
export function createOpenContextTools({ Type, env = process.env, settings = loadSettings(env) }) {
  const journal = createJournal(settings.journalDir);
  const tools = [];

  async function retrieval(kind, route, payload, signal) {
    if (!settings.retrieval) throw new Error("the recorded retrieval API is not configured for this run");
    const { reply } = await postRetrieval(settings.retrieval, route, payload, signal);
    if (!reply || typeof reply !== "object") throw new Error("the retrieval API returned no event");
    return reply;
  }

  if (settings.retrieval) {
    tools.push({
      name: TOOL_NAMES.fetch,
      label: "Recorded public fetch",
      description: "Fetch one public HTTPS URL through ScanEval's recorded retrieval service. Only declared public "
        + "origins are reachable; private or undeclared destinations are denied. Every attempt is recorded. "
        + "Returns the HTTP outcome and the response body as UTF-8 text, truncated.",
      parameters: Type.Object({ url: Type.String({ description: "An https:// URL on a declared public origin" }) }),
      async execute(_id, params, signal) {
        const url = params?.url;
        if (typeof url !== "string" || !url || url.length > 8192) {
          journal.write({ event: "tool", tool: TOOL_NAMES.fetch, outcome: "rejected", reason: "invalid url" });
          throw new Error("url must be a string of at most 8192 characters");
        }
        let reply;
        try {
          reply = await retrieval("fetch", "/fetch", { url, source: "browser_tool" }, signal);
        } catch (error) {
          journal.write({ event: "tool", tool: TOOL_NAMES.fetch, url: journalValue(url), outcome: "error",
            error: journalValue(error instanceof Error ? error.message : String(error)) });
          throw error;
        }
        journal.write({ event: "tool", tool: TOOL_NAMES.fetch, url: journalValue(url),
          outcome: reply.outcome === "ok" || reply.outcome === "http_error" ? "returned" : "refused", ...retrievalJournal(reply) });
        if (reply.outcome !== "ok" && reply.outcome !== "http_error") {
          throw new Error(`retrieval ${reply.outcome}: ${String(reply.error ?? "no reason given").slice(0, 500)}`);
        }
        return textResult(retrievalText("fetch", reply), retrievalJournal(reply));
      },
    });
    if (settings.search) {
      tools.push({
        name: TOOL_NAMES.search,
        label: "Recorded public search",
        description: "Search the public web through ScanEval's configured, recorded search endpoint. Every query is "
          + "recorded. Returns the endpoint's raw response as UTF-8 text, truncated.",
        parameters: Type.Object({ query: Type.String({ description: "Search query, at most 4096 characters" }) }),
        async execute(_id, params, signal) {
          const query = params?.query;
          if (typeof query !== "string" || !query || query.length > 4096) {
            journal.write({ event: "tool", tool: TOOL_NAMES.search, outcome: "rejected", reason: "invalid query" });
            throw new Error("query must be a non-empty string of at most 4096 characters");
          }
          let reply;
          try {
            reply = await retrieval("search", "/search", { query, source: "browser_tool" }, signal);
          } catch (error) {
            journal.write({ event: "tool", tool: TOOL_NAMES.search, query: journalValue(query), outcome: "error",
              error: journalValue(error instanceof Error ? error.message : String(error)) });
            throw error;
          }
          journal.write({ event: "tool", tool: TOOL_NAMES.search, query: journalValue(query),
            outcome: reply.outcome === "ok" || reply.outcome === "http_error" ? "returned" : "refused", ...retrievalJournal(reply) });
          if (reply.outcome !== "ok" && reply.outcome !== "http_error") {
            throw new Error(`search ${reply.outcome}: ${String(reply.error ?? "no reason given").slice(0, 500)}`);
          }
          return textResult(retrievalText("search", reply), retrievalJournal(reply));
        },
      });
    }
  }

  tools.push({
    name: TOOL_NAMES.git,
    label: "Repository history (read-only)",
    description: "Read-only access to the repository's own Git history, which ends at the scanned commit. "
      + "Operations: log (commits, optionally for one path), show (one commit's stat and patch), file (a file at "
      + "a revision), blame (line authorship), grep (fixed-string search at a revision). Revisions are HEAD or a "
      + "commit id, optionally with ~N or ^N. Paths are relative to the repository root.",
    parameters: Type.Object({
      op: Type.Union(GIT_OPERATIONS.map((value) => Type.Literal(value))),
      rev: Type.Optional(Type.String({ description: "HEAD or a commit id, optionally with ~N/^N" })),
      path: Type.Optional(Type.String({ description: "Repository-relative path" })),
      pattern: Type.Optional(Type.String({ description: "Fixed string for grep" })),
      max_count: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
      start_line: Type.Optional(Type.Integer({ minimum: 1 })),
      end_line: Type.Optional(Type.Integer({ minimum: 1 })),
    }),
    async execute(_id, params, signal) {
      let args;
      try {
        args = gitArguments(settings.repo, params ?? {});
      } catch (error) {
        journal.write({ event: "tool", tool: TOOL_NAMES.git, op: journalValue(params?.op ?? null), outcome: "rejected",
          error: journalValue(error instanceof Error ? error.message : String(error)) });
        throw error;
      }
      const result = await runGit(settings, args, env, signal);
      const text = result.stdout.toString("utf8");
      journal.write({ event: "tool", tool: TOOL_NAMES.git, op: params.op, rev: journalValue(params.rev ?? null),
        path: journalValue(params.path ?? null), outcome: result.code === 0 ? "returned" : "error",
        exit_code: result.code, output_bytes: result.stdout.length, truncated: text.length > MAX_GIT_TEXT,
        ...(result.failure ? { failure: result.failure } : {}) });
      if (result.code !== 0) {
        throw new Error(`git ${params.op} failed: ${clip(result.stderr.toString("utf8").trim() || result.failure || "no message", 2_000)}`);
      }
      return textResult(clip(text, MAX_GIT_TEXT) || "(no output)", { op: params.op, bytes: result.stdout.length });
    },
  });

  tools.push({
    name: TOOL_NAMES.read,
    label: "Read repository source",
    description: "Read a file of the scanned repository, with line numbers, or list a directory. Paths are relative "
      + "to the repository root and cannot leave it.",
    parameters: Type.Object({
      op: Type.Optional(Type.Union([Type.Literal("file"), Type.Literal("list")])),
      path: Type.Optional(Type.String({ description: "Repository-relative path" })),
      start_line: Type.Optional(Type.Integer({ minimum: 1 })),
      max_lines: Type.Optional(Type.Integer({ minimum: 1, maximum: 20000 })),
    }),
    async execute(_id, params) {
      try {
        const { text, details } = readSource(settings, params ?? {});
        journal.write({ event: "tool", tool: TOOL_NAMES.read, op: params?.op ?? "file",
          path: journalValue(details.path), outcome: "returned" });
        return textResult(text || "(empty)", details);
      } catch (error) {
        journal.write({ event: "tool", tool: TOOL_NAMES.read, op: journalValue(params?.op ?? "file"),
          path: journalValue(typeof params?.path === "string" ? params.path : null), outcome: "error",
          error: journalValue(error instanceof Error ? error.message : String(error)) });
        throw error;
      }
    },
  });

  journal.write({ event: "loaded", version: OPEN_CONTEXT_TOOLS_VERSION, tools: tools.map((tool) => tool.name),
    retrieval_configured: settings.retrieval !== null, search_registered: tools.some((tool) => tool.name === TOOL_NAMES.search) });
  return { tools, journal, settings };
}

export function sha256File(path) {
  const data = readFileBounded(path, 16 * 1024 * 1024);
  return data === null ? null : `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function readFileBounded(path, limit) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return null;
  }
  try {
    const status = fstatSync(descriptor);
    if (!status.isFile() || status.size > limit) return null;
    const buffer = Buffer.alloc(status.size);
    let offset = 0;
    while (offset < buffer.length) {
      const read = readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    return buffer.subarray(0, offset);
  } finally {
    closeSync(descriptor);
  }
}
