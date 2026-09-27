# Native CLI collectors

`scaneval.collectors` turns the records an agent CLI writes for itself into ScanEval trace
events. It exists so that a harness which shells out to Claude Code or Codex becomes
observable **without being edited**: the harness runs exactly as it did, and a collector is
pointed afterwards at what the run left behind.

That is the value and it is also the limit. A collector is a reader, not a wrapper. It sees
what the CLI chose to write down, which is never the whole invocation, so every event it
emits says where it was read from (`metadata.source`) and carries `capture_status: partial`
wherever the reading was derived rather than observed. **An event a collector did not emit is
not evidence that the thing did not happen.** It is evidence that the CLI did not write it
down where the collector could read it.

Nothing here spawns a process, patches a client, or makes a network call. `import_stream_json`
and `import_exec_jsonl` are pure readers over text you hand them. `find_transcripts` and
`import_transcript` are the two functions that touch the filesystem — to glob a directory you
name and to open a file it returned — and they treat those files as hostile input, because
they are written by another process after the scan began. See
[A transcript is a file somebody else is still writing](#a-transcript-is-a-file-somebody-else-is-still-writing).

## The API

```python
from scaneval.collectors import ImportSummary
from scaneval.collectors import claude_code, codex
```

| Name | What it does |
|---|---|
| `ImportSummary` | Frozen dataclass returned by every importer: `events`, `model_turns`, `tool_calls`, `tool_results`, `spans`, `unknown_records`, `malformed_lines`, `unmatched_tool_results`, `undelivered_tool_results`, `capture` (the Contract 3 capture-status keys), `notes`. |
| `claude_code.find_transcripts(session_id, *, projects_dir=None)` | Returns the main transcript for that session followed by its `subagents/*.jsonl`. `projects_dir` defaults to `~/.claude/projects`. Returns `[]` rather than raising when nothing matches **or when the ID is refused** — see [A session ID is untrusted input](#a-session-id-is-untrusted-input). |
| `claude_code.session_id_is_usable(session_id)` | Whether an ID may be looked up at all. Call it first to tell "refused" from "no transcript". |
| `claude_code.import_transcript(observer, path, *, workspace_root, call_id, sidechain=False, agent_id=None)` | Reads one transcript file, no-follow and size-bounded. `sidechain` and `agent_id` are defaults; a record that states its own wins. A refused or truncated read is reported in the returned summary, never raised. |
| `claude_code.import_stream_json(observer, lines, *, workspace_root, call_id)` | Reads `claude -p --output-format stream-json --verbose` output. |
| `claude_code.parse_result_object(text)` | Parses `claude -p --output-format json` stdout. Returns `None` for anything that is not a `type: "result"` object. |
| `codex.import_exec_jsonl(observer, lines, *, workspace_root, call_id)` | Reads `codex exec --json` output. |
| `workspace_roots(root_or_roots)` | Normalizes a `workspace_root` argument to an ordered, deduplicated tuple. Raises `ValueError` on an empty sequence or a non-path element. |

`observer` is a `scaneval.observer.Observer` whose recording mode the caller chose.
`workspace_root` is the scanned workspace — see
[Pass every spelling of the workspace root](#pass-every-spelling-of-the-workspace-root)
below, because on macOS one directory has two. `call_id` is the caller's logical invocation ID: `model.request`, `model.response` and
`context.selection` events carry it, and each turn gets `attempt_id = "<call_id>/turn-<n>"`.
Tool events carry the CLI's own tool-use ID as their `call_id` instead, so a start and an end
join without a guess.

## The vocabulary each importer emits

Consistent with Contract 3. `metadata.source` is `claude_code_transcript`,
`claude_code_stream_json` or `codex_exec_json`; `metadata.route` is `claude` or `codex`.

| Event | When | Notable metadata |
|---|---|---|
| `model.request` | Once per assistant **message** (Claude) or per `turn.started` (Codex) | `attempt: 1`, `retries_observable: false`, `model_requested: null` |
| `model.response` | Paired with each request by `attempt_id` | `usage` (four counters), `usage_available`, `model_served`, `session_id`, `stdout_chars`, `failure_kind` (`error` is always `null` — see below) |
| `tool.start` | Per `tool_use` block / per tool `item.started` | `tool_name`, `input_summary`, `sidechain`, `agent_id` |
| `tool.end` | Per `tool_result` / per tool `item.completed` | `is_error`, `result_chars`, `spans`, and for Codex `exit_code` and `status` |
| `context.selection` | Per file-read tool result **that a later model turn consumed** — see [Returned is not delivered](#returned-is-not-delivered) | `stage: "tool_result"`, `spans`, `span_count`, `capture_status: partial` |
| `observer.error` | Once per reading loss: unreadable lines, a refused file, a truncated read | `malformed_lines` or `max_bytes`, `capture_status: unavailable` |

A span is `{path, start_line, end_line, chars, sha256, truncated, original_chars, role}` with
`sha256` over exactly the text the tool delivered. `role` is always `"other"`: a role says why
a *harness* supplied a span, and these spans were read out of a tool result that says only
that the model asked for the file. `truncated` is `null` rather than `false` when the record
did not report the file's full length, because `false` there would assert a completeness
nothing in the record supports.

`capture` is never `complete` for any key. Findings are `not_applicable`: a CLI transcript has
no finding lifecycle in it, because the harness that reads the model's answer is where a
finding becomes a finding.

## What the CLIs actually write

Verified against real runs, not assumed from a contract. Where the real shape differs from a
reasonable guess, the difference is called out.

### Claude Code session transcript

Lives at `~/.claude/projects/<slug-of-cwd>/<session-id>.jsonl`, with subagent files under
`~/.claude/projects/<slug>/<session-id>/subagents/agent-<id>.jsonl`.

- **An assistant record is a content block, not a turn.** One API response is written as
  several records sharing `message.id`, `message.usage` and `requestId`, differing only by
  `apiBlockIndex`. The importer accumulates blocks per `message.id` and emits one
  request/response pair per message. Emitting per record would report twice the turns and
  **double-count every token**.
- A tool result is a `user` record whose `message.content` holds a `tool_result` block, plus a
  top-level `toolUseResult` whose shape depends on the tool: `Read` gives
  `{type, file: {filePath, content, numLines, startLine, totalLines}}`, `Bash` gives
  `{stdout, stderr, interrupted, ...}`, `Glob`/`Grep` give a listing or filenames, `Agent`
  gives `{agentId, status, description, resolvedModel, ...}`.
- Most of a transcript is bookkeeping. In the committed fixture, taken from a real
  single-question session, 6 of 32 records are message records; the rest are `attachment`,
  `queue-operation`, `last-prompt` and `atis-latch`, and a longer session adds `ai-title`,
  `mode` and `summary`. These are counted in `unknown_records` and their names listed in
  `notes`, never raised on: a reader that had to know every bookkeeping type would break on
  the next CLI release.

### Claude Code `-p --output-format stream-json --verbose`

The same conversation with different spellings — `tool_use_result` for `toolUseResult`,
`request_id` for `requestId` — plus records a transcript has no equivalent of. The importer
accepts both spellings everywhere.

- `system` / `init` names the model, the session ID and the tool list.
- The final `result` record carries `subtype`, `is_error`, `num_turns`, `session_id`,
  `total_cost_usd`, `usage` and `duration_api_ms`. These are attached to the **last**
  `model.response` under the `invocation_*` keys — never over that turn's own `usage`, see
  [Whose tokens are these](#whose-tokens-are-these) — and repeated in `ImportSummary.notes`.
- A real run also emitted `system` records with subtypes `hook_started`, `hook_progress` and
  `hook_response`, and `rate_limit_event` records. None are in any published record list.
  They are counted, never raised on.

### Codex `codex exec --json`

- Events are `thread.started` (with `thread_id`), `turn.started`, `item.started` /
  `item.updated` / `item.completed`, and `turn.completed` / `turn.failed`.
- `turn.started` carries **no fields at all** — no model, no prompt, no parameters.
- Usage arrives only on `turn.completed`, spelled in Codex's own vocabulary:
  `input_tokens`, `output_tokens`, `cached_input_tokens`, `cache_write_input_tokens`,
  `reasoning_output_tokens`. The importer maps `cached_input_tokens` to
  `cache_read_input_tokens` and `cache_write_input_tokens` to `cache_creation_input_tokens`.
  `reasoning_output_tokens` has no Contract 3 key and is **not** folded into `output_tokens`,
  which would inflate a counter read across routes.
- `command_execution` items carry `command`, `aggregated_output`, `exit_code` and `status`.
- `codex exec` needs `--skip-git-repo-check` outside a trusted git repository, and reads the
  prompt from stdin if one is not given positionally.

## What a collector cannot capture

These are format limits, not reader defects. They are the reason `capture` says `partial`.

- **Retries are invisible.** A CLI that retried internally wrote one turn. Every
  `model.request` says `retries_observable: false` so a reader cannot mistake one request
  event for one attempt.
- **A shell command is never a span.** Codex reads files by running `cat`, `nl` or `rg`, and
  Claude can too. Nothing in the result says which file the output came from or which lines
  those were, so no span is claimed and Codex's `context_selection` is `unavailable` — which
  is a different answer from `partial` and Contract 5 reads the difference.
- **Subagent transcripts carry no `toolUseResult`.** A subagent's `Read` appears with its
  delivered text and no file path, line range or length. So a subagent import produces
  `tool.start` / `tool.end` but **no spans at all**, and its `context_selection` is
  `unavailable`. This was verified on two real subagent files.
- **Subagent transcripts are only found when the session directory exists.** The CLI creates
  `<session-id>/subagents/` only when a subagent actually ran and wrote there. An empty
  result from `find_transcripts` is not evidence that no subagent ran.
- **`stream-json` output does not include subagent tool calls.** A `Task` tool use appears and
  its result appears; the subagent's own turns and tool calls do not.
- **No prompt is recorded for a `-p` invocation.** The prompt came from `argv`, so
  `prompt_chars` is `null` on a stream-json request. A transcript does carry the user turn, so
  there `prompt_chars` is filled and, in content mode, `content.prompt`.
- **Codex reports no model identity**, so `model_served` is `null` on every Codex response.
- **No collector produces finding events.** A finding is made by the harness that reads the
  model's answer, and that boundary is the harness's to emit at.

## A failure message is free text, not a code

When a CLI fails it writes a message for a human terminal. That message routinely quotes the
command that failed, the output it produced, the traceback and the source line that raised,
and absolute paths on the operator's machine. Copying it into `metadata.error` would walk
all of that past the metadata/content separation the rest of this package keeps — through a
field nobody reads as a content field.

So a failure is split in two:

- **`metadata.failure_kind`** is a code from a closed set: `turn_failed`, `item_error`,
  `result_error`, `unknown` (`scaneval.collectors.FAILURE_KINDS`). An unrecognized kind
  becomes `unknown` rather than being passed through, because `failure_kind` is a field
  consumers group by and one CLI's stray string would open the vocabulary without anyone
  deciding to.
- **`metadata.error`** is always `null`. Metadata carries no prose the CLI wrote — not the
  message, and not a bounded prefix of it either.
- **`content.error`** holds the message whole, and only in content mode. In `metadata` mode
  it is read, used to decide the kind, and dropped.

An earlier version put a 120-character, path-relocated summary in `metadata.error`.
Relocating made an operator path impossible, but nothing made the first 120 characters stop
being whatever the message happened to open with — and for a traceback that is the line of
source that raised. **Bounded source is still source**, and Contract rule 5 gives metadata
none of it. So the summary is gone rather than shortened further: `failure_kind` says a
failure happened and what kind, and the prose has exactly one destination.

`_Import.failure` takes the message and returns only the kind, so there is no value in the
codebase that carries a classification and prose together toward a metadata payload.

The other CLI-authored strings that *do* reach metadata are identifiers and enums rather
than prose — `result_subtype` and a Codex item `status` — and those are bounded to 60
characters, because they are short enums today and "today" is not a property metadata should
rely on.

Two hand-built fixtures exist for exactly this and are used in both recording modes:
`codex-exec-edge-cases.jsonl` (a `turn.failed`, an `error` item, and a failed
`command_execution`) and `claude-code-stream-json-error.jsonl` (a result record whose
`result` field is the error rather than the answer). Both quote `/outside/private/credentials`
and a `return eval(raw)` source line, and the tests assert neither reaches metadata in either
mode while both reach `content.error` in content mode.

Codex's `error` items are reported on the turn they occurred in rather than dropped, since
they are the only trace of a failure that a later `turn.completed` would otherwise paper
over. The turn's own `is_error` and `result_subtype` are unchanged by this: a turn that
completed with an error item inside it gets `is_error: false`, `result_subtype: "completed"`
and `failure_kind: "item_error"`, because both facts are true and the trace reports both
rather than picking one. A `turn.failed` outranks an error item inside it.

## Pass every spelling of the workspace root

`workspace_root` takes **one root or a sequence of roots**
(`Path | str | Sequence[Path | str]`). Each is tried in order and the first that contains the
path wins; a relative path is resolved against the first. Pass every spelling the run could
have used, because the collector cannot discover the extras for itself.

**On macOS you must pass two.** A temporary directory is `/var/folders/...` and its realpath
is `/private/var/folders/...` — the same directory under two true names. A real DeepSec run
handed the Claude Agent SDK the `/var/...` spelling; the SDK recorded its `cwd` and every
`Read` `filePath` under `/private/var/...`. The two strings genuinely differ, so a
single-root import filed **every file the agent read** as `external:<basename>`, and no span
could be joined to a label. Nothing was wrong except that the collector had been told only
one of the directory's two names.

```python
summary = import_transcript(
    observer, path,
    workspace_root=(source_dir, source_dir.resolve()),   # handed spelling, then realpath
    call_id=call_id,
)
```

`workspace_roots` deduplicates while keeping order, so passing both unconditionally is
correct on every platform: where the two are the same string you get one root.

**The collector still resolves no symlink and touches no filesystem.** That is why the
caller supplies the second spelling rather than the collector deriving it. A trace is
frequently read on a machine that is not the one the run happened on, sometimes long after
the temporary directory is gone; a collector that called `realpath` would get an answer about
the reader's filesystem and quietly pass it off as a fact about the run. Only the caller was
there when the run happened, so only the caller can say what the directory was also called.

An empty sequence, or an element that is not a path, raises `ValueError` — at the top of the
importer, before any file is opened. This is wiring rather than a record: a collector that
accepted "no workspace" would mark every path in the run external and report a clean import
while doing it.

## Returned is not delivered

A tool result proves the tool returned some text. It does not prove a model was given it.
Those are different facts, and a coverage claim rests on the second one.

So a file read produces its `tool.end` and its span immediately — the tool really did return
that content — but the `context.selection` is **held** until a later assistant turn appears
in the record. That turn is the evidence of delivery, and the selection is emitted just ahead
of its `model.request`, so the trace reads in the order the conversation happened: these
lines arrived, then the model was asked again.

A record that stops right after a read therefore claims no selection for it. Those reads are
counted in `ImportSummary.undelivered_tool_results` with a note, and `capture.context_selection`
is `unavailable` rather than `partial` because no selection was claimed at all. Without this,
a transcript truncated one line after a `Read` would make `scaneval.diagnostics` report that
file as `included` on the strength of a delivery nothing in the record shows.

The rule is about what a record shows, so it is identical for session transcripts and for
stream-json.

### What counts as proof

Since a turn is the evidence, an importer that accepted any `assistant` record as a turn
would accept a damaged line as evidence. A record releases held context only when it is a
**valid, distinct model message**:

- it carries a `message` object holding either content or a usage report — a bare
  `{"type": "assistant", "uuid": "..."}` is a marker or an error stub, not a response;
- its `message.id` (or fallback key) has not already been emitted as a turn, so a replayed
  record is the message we already saw rather than a second one. Accepting one would double
  that turn's usage and count as a second delivery.

The per-block records a real message is written as are *not* replays: they share a
`message.id` with the turn currently open and accumulate into it, and the replay check only
sees a key whose turn was already emitted.

Records failing the test open no turn, release nothing, and are counted in `unknown_records`
under the names `assistant:not-a-model-message` and `assistant:replayed-message`, with a note
saying how many there were and what their presence did not buy.

The test is written about **shape**, not about any CLI version — it asks whether a record
contains a response, not whether it looks like one a particular release writes.

## Whose tokens are these

Two scopes, two sets of keys, and they must not be mixed.

`usage` and `usage_available` on a `model.response` are always **that turn's own**, read from
its own `message.usage`. The `result` record's figures describe the whole `claude -p`
invocation, and the last turn is merely where the CLI happened to print them, so they go on
the last response under their own names:

| Key | Scope |
|---|---|
| `usage`, `usage_available` | This turn |
| `cost_usd_cli_reported`, `num_turns`, `duration_api_ms` | This turn — always `null`, because a transcript reports none of them per turn |
| `invocation_usage`, `invocation_cost_usd_cli_reported`, `invocation_num_turns`, `invocation_duration_api_ms` | The whole invocation; non-null only on the last response |

Writing the invocation totals into the per-turn keys made the last response claim the
invocation's figures as its own, so summing `usage` across responses counted the last turn
twice. In the committed fixture that was 10 and 18 input tokens per response against an
invocation total of 18. Now a reader who wants the invocation total reads one `invocation_*`
key, a reader who wants per-turn cost adds up `usage`, and neither can silently get the other.
The four `invocation_*` keys are present and `null` on every other response, so consumers read
one key shape rather than testing for absence.

## A session ID is untrusted input

A session ID is not a constant. It is read out of a CLI's stdout or out of records a scanner
wrote, and it then names a path — so it decides which files get imported.

`find_transcripts` used to interpolate it into a glob pattern
(`projects_dir.glob(f"*/{session_id}.jsonl")`). A recorded ID of `*` or `[a-f]*` therefore
matched **every session under the projects directory**, and unrelated conversations could be
imported into a trace as though they belonged to the scan. Two changes close it:

1. **The ID is validated against a literal shape first**, `SESSION_ID_PATTERN` =
   `^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$`. That admits the UUIDs Claude Code issues and the
   `agent-<hex>` names beside them, and admits no glob metacharacter (`*?[]{}`), no
   whitespace, no dot and no separator — by construction rather than by a blocklist, because
   a blocklist has to be complete while an allowlist only has to be correct.
2. **Lookup is by joining, never by pattern.** The project directories are iterated and
   `directory / f"{session_id}.jsonl"` and `directory / session_id / "subagents"` are tested
   by `lstat`, with the same regular-file and boundary checks as everywhere else. The only
   glob left is a literal `*.jsonl` *inside* the joined subagents directory, so no character
   of the ID ever reaches the matcher. A subagent file whose own name contains a
   metacharacter is still found, because the narrowing is about what counts as a pattern, not
   about what can be found.

`find_transcripts` answers both "refused" and "no transcript" with an empty list, which is
right for a lookup and wrong for a capture report. `session_id_is_usable(session_id)` is
exported so an adapter can tell them apart: the first is a scanner record that cannot be
trusted and is worth a note, the second is an ordinary run that kept no log.

## A transcript is a file somebody else is still writing

The files `find_transcripts` returns are written by the CLI, by a process this collector
does not control, *after* the scan it is describing began. They are therefore input, not
assets, and between the run and the import a name can become a link to a host file, a named
pipe, a device node, or something enormous. Three guards, each closing a hole the others
leave open:

| Guard | Stops |
|---|---|
| `lstat` + resolved-parent boundary check in `find_transcripts` | A symlink at the name, and a symlinked *directory* above it — swapping `<projects>/<slug>` for a link to `/etc` would otherwise make every `*.jsonl` under it look like a transcript. |
| `O_NOFOLLOW` on open | A symlink swapped in *after* discovery checked the name. Discovery and reading are two different moments, and only the second one counts. |
| `O_NONBLOCK` on open, then `fstat` on the descriptor | A FIFO. Opening one for reading blocks until somebody opens the write end, so without the flag a swapped-in pipe stops the import forever, with no error and nothing to time out. With it the open returns at once and `fstat` refuses the pipe for what it is. Checking the *descriptor* rather than the name also makes the check race-free: stat-then-open asks about a name twice and can get two different files. |

The read is then streamed in chunks under `MAX_TRANSCRIPT_BYTES` (64 MiB — far above any
real session, the largest observed being under 200 KiB, and far below a figure that could
exhaust a scanning host). Past the bound the read stops.

**Neither refusal nor truncation raises.** A harness calling a collector has already
finished its scan, and a log that turned out to be a device node must cost the trace and
never the run. Both come back through the `ImportSummary` a caller already reads:

- **Refused** — a `refused: …` note, an `observer.error` event, and `capture` with every
  observable key `unavailable`. Not `partial`: partial says some of a category was captured,
  and a refused read captured none of it.
- **Truncated** — a `truncated: …` note and an `observer.error` carrying `max_bytes`. The
  events already emitted are real and are kept; what is unknown is what came after the bound.
  The trailing partial line is dropped rather than counted as malformed, because it is half
  of a record this reader chose not to finish, and counting it as damage would blame the file
  for the bound.

`import_stream_json` and `import_exec_jsonl` take an iterable of lines rather than a path, so
the caller owns that read and none of this applies to them.

## Transcripts are the operator's files

A Claude Code transcript is written under the operator's home directory and **is content**. It
quotes absolute paths from that machine, and its `attachment` records were observed carrying
the session's entire system prompt, the configured MCP servers, the installed skills and
agents, the hook commands that ran with their stdout, the working-directory snapshot, and the
account email address.

Two consequences, both enforced in code rather than left to care:

1. **Paths never pass through.** Every path in an event is workspace-relative; anything
   outside every root becomes `external:<basename>` and is counted in the notes. This includes
   paths *inside free text*: the absolute paths in a shell command are rewritten before the
   command reaches `metadata.input_summary`, because a command is a string and strings are not
   audited as path fields. `tests/test_v2_collectors.py::test_no_event_any_importer_emits_carries_an_absolute_path_in_its_metadata`
   searches every string of every metadata payload for an absolute path.
2. **Content only ever reaches `content`.** In `metadata` mode no file text is built into a
   payload at all — not dropped later, not built. `metadata` carries hashes, line ranges and
   sizes. This is Contract rule 5 and
   `::test_metadata_mode_holds_no_file_content_anywhere_and_content_mode_holds_it` pins it.

## Regenerating the fixtures

The fixtures in `schema/v2/fixtures/collectors/` came from real CLI runs against a synthetic
two-file repository and were then scrubbed. Real runs are the point: they are why the reader
knows an assistant record is a content block and that a subagent file has no `toolUseResult`.

### 1. A synthetic workspace

Two files you wrote yourself. Never a third-party repository, and never real source.

```bash
mkdir -p /tmp/collector-fixture/repo && cd /tmp/collector-fixture/repo
# app.py with an eval( call, util.py with one helper function
```

### 2. Tiny real runs

Keep them small and use the cheap model. Each produces one fixture.

```bash
SESSION=$(python3 -c 'import uuid; print(uuid.uuid4())')

# stream-json + the session transcript
claude -p --model claude-haiku-4-5 --output-format stream-json --verbose \
  --session-id "$SESSION" \
  "Read app.py and report which line calls eval. Use the Read tool." > stream-json.jsonl

# a subagent transcript
claude -p --model claude-haiku-4-5 --output-format stream-json --verbose \
  --session-id "$SESSION2" \
  "Use the Task tool to launch exactly one general-purpose subagent whose whole job is to
   Read util.py and report the name of the function it defines."

# the single result object
claude -p --model claude-haiku-4-5 --output-format json "Reply with the single word ok" \
  > result.json

# codex
codex exec --json --skip-git-repo-check --sandbox read-only -C "$PWD" \
  "Read app.py and report which line calls eval" > codex-exec.jsonl
```

Then locate the transcripts with the collector's own finder:

```python
from scaneval.collectors.claude_code import find_transcripts
find_transcripts(session_id)   # main file first, then subagents/*.jsonl
```

### 3. Scrub, always

```bash
python scripts/sanitize_native_trace.py --kind transcript \
  --workspace /tmp/collector-fixture/repo \
  --in ~/.claude/projects/<slug>/<session>.jsonl \
  --out schema/v2/fixtures/collectors/claude-code-transcript.jsonl
```

`--kind` is `transcript`, `stream-json`, `result-json` or `codex-exec`.

The script is an **allowlist**, not a search-and-replace. The record types the collectors
actually read are rewritten field by field; every other record is reduced to a stub keeping
only its type and its structural links. That is what keeps the system prompt, the environment
snapshot, the hook commands and the account email out of the repository without the script
having to anticipate each of them, and it means a field a future CLI version adds is dropped
by default rather than published by default.

What it does:

- The workspace path becomes `/workspace` — absolute, so the fixture stays a file the
  importers parse exactly as they parse a real one, and so the tests can pass
  `workspace_root=Path("/workspace")`. It is the `<workspace>` placeholder the repository
  rules call for, spelled so it is still a path.
- Any other absolute path becomes `/redacted/<basename>`.
- Email addresses become `operator@example.invalid`.
- No committed file of this package spells a home-directory path in any form — not even a
  synthetic placeholder account. The adversarial fixtures use `/outside/private/...` instead,
  which is an absolute path outside the workspace and exercises the same relocation branch.
- Session, request, message, tool-use, thread and record UUIDs become fixed placeholders,
  **deterministically**: the same native ID always maps to the same stub, so `parentUuid` still
  points at a `uuid` and `tool_use_id` still points at a `tool_use`, and the fixture still
  exercises the pairing logic.
- Thinking-block text and its signature are replaced; the thinking is model output about a
  real session and the signature is an opaque token no collector reads.
- The `tools` list in a `system`/`init` record is replaced with a short generic list, because
  the real one names the operator's MCP servers.
- Finally it **audits its own output** and refuses to write a file in which a home path, an
  unscrubbed workspace path, or an email address survived.

`tests/test_v2_repository_hygiene.py` is the backstop and must pass on the result.

### The fixtures that are not from a real run

Three are hand-built in the same record shape, for branches a short successful run cannot
produce. Their code is synthetic and their shape is copied from the real files.

| Fixture | Covers |
|---|---|
| `claude-code-edge-cases.jsonl` | A line that is not JSON, valid JSON that is not a record, a read outside the workspace, a truncated read, a `tool_result` whose `tool_use` was never seen, and a failed `Bash` call. |
| `codex-exec-edge-cases.jsonl` | A `turn.failed`, an `error` item, and a failed `command_execution` — each with failure text quoting `/outside/private/credentials` and a `return eval(raw)` source line. |
| `claude-code-stream-json-error.jsonl` | A result record whose `result` field is the CLI's error message rather than the model's answer, carrying the same home path and source excerpt. |

The last two exist to be *adversarial*: they are the input the closed-code-plus-bounded-summary
rule above is there to survive, and the tests drive them in both recording modes. A change
that let native failure prose back into `metadata` fails against them rather than shipping.
