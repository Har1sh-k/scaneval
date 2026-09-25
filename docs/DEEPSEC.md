# The DeepSec adapter

DeepSec (`vercel-labs/deepsec`, pinned here at 2.3.10) is a third-party scanner ScanEval evaluates like any other. It is not ours, it is never modified, and no part of it is patched, wrapped, or injected into. The adapter runs the installed CLI, preserves everything it wrote, and translates its exported findings into claims.

This document says what the adapter runs, what it can and cannot observe, and which of those limits are DeepSec's and which are ScanEval's. The capture matrix below is the matrix `scaneval.adapters.deepsec.capture_status` returns for a run, cell for cell, and `tests/test_v2_deepsec.py::test_the_documented_capture_matrix_is_the_one_capture_status_returns` parses both tables out of this file, builds every run they describe, and compares each cell against what that function returns. The document is the only copy of the matrix.

## How DeepSec works, and why that decides everything here

DeepSec scans in two stages and writes both down.

1. `scan` runs regex matchers over the project and records a `CandidateMatch` on each file it hit, inside `data/<project>/files/<path>.json`.
2. `process` batches those files and hands each batch to an agent built on the Claude Agent SDK. Each file in the batch gains an `analysisHistory` entry and, when the agent found something, a `Finding`.
3. `export --format json` renders the findings for an issue tracker.

Two facts about stage 2 shape every event this adapter emits.

**The numbers on one file are that file's share of a batch.** DeepSec divides a batch's API duration, turn count, cost and token counts among the files in the batch, and every file in the batch carries the same `agentSessionId`. A single file's `costUsd` is a fraction of one model conversation, and `numTurns` is routinely a fraction like `1.333`. So every aggregate here is a sum over the files that name one session, and every event built from one carries `aggregation: "sum_of_per_file_shares"`. Read such a number as a reconstruction of one batch, never as a measurement of one model call.

**`durationMs` is a share too, and one DeepSec version disagreed.** The installed 2.3.10 divides it like everything else: a real run of this adapter recorded 45316.33 ms on each of a batch's three files for a batch its own stdout timed at 135.9 seconds. It is summed. A record from an older DeepSec showed the same whole number on every file of a batch instead, and reading that as the rule made the adapter take a maximum, which reported a 135.9-second batch as a 45-second one. Where a session shows that older shape — every `durationMs` the same whole number while its other shares are fractional — the run records a note saying the duration may be duplicated rather than divided. The number stays the sum: guessing a different total from a guess about which version wrote the record would be worse than a flagged one. `durationApiMs` is summed too and can exceed the wall clock; it is DeepSec's own accounting of API time across turns, not elapsed time.

**Most input tokens arrive as cache reads.** The same run summed to `inputTokens: 100` against `outputTokens: 23546`, `cacheReadInputTokens: 352080` and `cacheCreationInputTokens: 68128`. The scan result's `usage` has only `input_tokens` and `output_tokens`, so a reader looking there alone sees a hundred input tokens for a four-minute run and should not conclude anything went wrong; all four counts are on the `model.response` event's `metadata.usage`.

**The agent decides inside the session.** Which candidates become findings is settled inside one Claude Agent SDK conversation. DeepSec records the outputs, not the deliberation: a candidate that produced no finding leaves nothing at all behind saying whether it was examined and dismissed or never looked at. That is why validation and filtering are permanently unavailable below.

Everything this adapter emits from DeepSec's own files carries `metadata.source: "harness_record"`, because it was read after the fact rather than observed as it happened.

## Configuration

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `deepsec_root` | yes | — | The DeepSec workspace holding `node_modules/.bin/deepsec`. `~` is expanded and the path is resolved before anything runs. Nothing is ever written here. |
| `model` | yes | — | The model handed to `--model`, e.g. `claude-haiku-4-5`. |
| `agent` | no | `claude` | `--agent`: `claude`, `codex` or `pi`. |
| `thinking_level` | no | unset | `--thinking-level`: `minimal`, `low`, `medium`, `high` or `xhigh`. Left off the command line when unset, so DeepSec's own default applies. |
| `limit` | no | unset | `--limit`: how many files `process` investigates. The main cost bound. |
| `batch_size` | no | unset | `--batch-size`: files per agent batch. |
| `concurrency` | no | `1` | `--concurrency`: batches in parallel. One by default, so a run is cheap to watch and its records interleave as little as possible. |
| `max_turns` | no | unset | `--max-turns`: conversation turns per batch. |
| `claude_projects_dir` | no | `~/.claude/projects` | Where the Claude Agent SDK leaves session transcripts, for the transcript import. |
| `claude_code_executable` | no | unset | Exported as `CLAUDE_CODE_EXECUTABLE` when set; left unset otherwise, so the SDK finds its own. |
| `project_id` | no | derived | The DeepSec project id. Derived from the input tree hash by default (see below). |

`ANTHROPIC_API_KEY` and `OPENAI_API_KEY` are passed through on top of the base set when the operator's environment holds them, and are never recorded. `HOME` is in the base set, which is what the local CLI login is read from. `NODE_OPTIONS` is deliberately not passed: node executes what it names, so `--require` in the operator's environment would run code inside the scanner while the record showed only a variable name.

## The project id

DeepSec names a data directory after the project id and refuses anything outside `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. The scan request an adapter receives carries the hash of the exported input but no snapshot id, so the default id is `scaneval-<first 16 hex of the input tree hash>`: deterministic, valid, and a name for exactly the bytes that were scanned. Set `config.project_id` to choose your own.

## The private workspace

DeepSec resolves `deepsec.config.ts` from the current working directory, walking up, and writes `data/` beside it. So the adapter builds a workspace of its own inside the run's raw output, at `raw/deepsec-workspace/`:

```
raw/deepsec-workspace/
  package.json          minimal, private, type: module
  deepsec.config.ts     one project, no plugins, ai: { mode: "local", provider: "local" }
  node_modules -> <deepsec_root>/node_modules
  data/<project>/       everything DeepSec wrote
```

The generated config declares exactly one project whose `root` is the exported source, and `plugins: []`, so only DeepSec's built-in matchers run and the scan is reproducible from that file alone. The `node_modules` symbolic link exists so the config's `import { defineConfig } from "deepsec/config"` resolves; it is never written through, and `scaneval.execution` cuts it when the staged output enters the bundle and records where it pointed. The operator's own workspace, its config and its `data/` are never read, listed, or touched.

That resolution is the one assumption here that no unit test can settle, because DeepSec loads a TypeScript config through `jiti` from the config file's own directory. It was checked against the real 2.3.10 CLI: a generated workspace with the symbolic link ran `scan` and `export` against a synthetic repository, DeepSec resolved the config, accepted the derived project id and the `--root` override, wrote `data/<project>/` where this adapter reads it, and exported an empty findings array. Only `process` was not exercised, because it calls a model.

## The commands it runs

Three CLI invocations in one workspace, sharing one timeout budget — each step is given whatever is left of `timeout_seconds`:

```
<deepsec_root>/node_modules/.bin/deepsec scan    --project-id <id> --root <source>
<deepsec_root>/node_modules/.bin/deepsec process --project-id <id> --root <source> \
    --agent <agent> --model <model> --concurrency <n> \
    [--thinking-level <level>] [--limit <n>] [--batch-size <n>] [--max-turns <n>]
<deepsec_root>/node_modules/.bin/deepsec export  --format json --project-id <id> --out raw/deepsec-export.json
```

`DEEPSEC_DATA_ROOT=data` is set explicitly so the data location does not depend on the operator's environment. The execution record's `command` is those three argv lists in order, separated by `&&`; each step's stdout and stderr is its own raw artifact.

## Two spellings of the workspace

The Claude Agent SDK records its working directory, and every path it read, under the platform's **real** path. ScanEval hands the scanner a private workspace under the system temporary directory, which on macOS is reached through a symbolic link: `/var/folders/…/source` is handed over, `/private/var/folders/…/source` is what the transcript says. The collectors compare paths textually and never resolve a symbolic link — deliberately, because resolving would touch the filesystem the trace is being *read* on rather than the one the run happened on. So the caller is the only party that can supply both spellings, and this adapter does:

```python
import_transcript(observer, path, workspace_root=(source_dir, source_dir.resolve()), …)
```

deduplicated when they are the same, handed spelling first. The execution record carries a note naming which spellings were used, with any home directory written as `~`.

This is not hypothetical. The first real run of this adapter passed one spelling, and every one of its eleven `context.selection` events came back with spans reading `external:server.js`, `external:ci.yml` and so on: eleven events that named a basename, said nothing about where in the workspace the model had read, and that the coverage attribution in `scaneval.diagnostics` could join to no target at all. The claims and the findings were unaffected — only the observation was.

## What lands in the bundle

| Artifact id | What it is |
| --- | --- |
| `deepsec-export` | The `export --format json` payload every claim cites. |
| `deepsec-config`, `deepsec-package-json` | The generated workspace files, so the run is reproducible. |
| `deepsec-scan-stdout` … `deepsec-export-stderr` | Each step's streams. |
| `deepsec-file/<path>.json` | One per `FileRecord`: candidates, findings, and the full `analysisHistory`. |
| `deepsec-run/<runId>.json` | One per `RunMeta`, scan and process alike. |
| `deepsec-debug/<name>` | One per parse-failure dump DeepSec wrote under `debug/`. |
| `deepsec-project/<name>` | Whatever the project directory holds at its top level: `project.json`, the `tech.json` a scan writes beside it, an `INFO.md` or `config.json` if there is one. Listed rather than named one by one, because DeepSec adds files here between versions. |

One thing to know before a bundle leaves the machine that made it: DeepSec's own `RunMeta` records the `pid` and the `hostname` of the machine it ran on. That is the scanner's record and is preserved verbatim, so a bundle shared outward carries it.

**A record path this run refused is import loss, never an absent record.** A symbolic link where a record file belongs was already refused by the read and counted; one standing where a record *directory* belongs used to match neither branch of the walk and was passed over in silence, so every record behind it vanished and the run read as a complete scan of what remained — replacing one directory under `files/` turned a two-file scan from `partial` into `success`. Every refusal is counted in `records.failures` now, named with its reason, which makes the run `partial` with `import_loss` and `bundles_resolved: false`. A stray file under `files/` that is simply not a record is not a refusal and is not counted.

They are registered where DeepSec wrote them rather than copied: the workspace is already inside the raw output the bundle keeps, so copying the tree beside itself would double every byte and prove nothing. Every read of one of those paths goes through the same enclosure and regular-file rule the own-harness adapter uses, so a record that is a symbolic link, that resolves outside the raw output, or that is a named pipe is a counted failure rather than a followed path or a blocked invocation.

## Claims

One claim per exported finding.

- `primary_location` spans the lines DeepSec cited: `start_line`/`end_line` from the minimum and maximum of `lineNumbers`, a single line when it cited one, and the file alone, with a note, when it cited none. No range is invented.
- `native_rule_id` is `deepsec:<vulnSlug>`.
- `native_id` is DeepSec's own `findingId`. `export --format json` in 2.3.10 renders a finding for an issue tracker and does not carry that id, so it is recovered from the file records by the pair DeepSec itself derives it from, `(filePath, title)`. A finding that cannot be joined gets no `native_id` and a note saying so.
- `allegation` is the finding's title with the `[SEVERITY]` prefix `export` renders stripped off, because the severity is already its own field.
- `native_severity` is DeepSec's severity; `evidence_text` is the exported description, truncated, with the whole of it still in the export artifact the claim cites.
- `kind` comes from the slug through the usual mapping, with the slug's separators removed first (`sql-injection` → `sqlinjection`). An `other-` slug the agent minted for a novel finding stays `unmapped` and keeps its native identity.

## Status

| Observation | Status | Error code |
| --- | --- | --- |
| A step exhausted the shared timeout budget | `timeout` | `timeout` |
| A step exited non-zero | `error` | `<step>_exit_<n>` |
| The export could not be read as a findings array | `error` | `unreadable_export` |
| An exported finding or a DeepSec record could not be imported | `partial` | `import_loss` |
| A file left in `status: "error"`, a parse-failure dump, or an agent refusal | `partial` | `deepsec_batches_failed` |
| A FileRecord carrying a status DeepSec does not declare, or none at all | `partial` | `invalid_record_status` |
| A FileRecord left `pending` or `processing` — scanned, no verdict reached | `partial` | `scope_incomplete` |
| None of the above | `success` | — |

`deepsec_batches_failed` is not cosmetic: each of those means part of the input reached no verdict, so the run cannot stand as a complete or quiet observation of the files it covers, and the message carries the counts.

**Only `analyzed` means DeepSec finished with a file.** Its own enum is `pending | processing | analyzed | error`, and its own metrics count everything but `analyzed` as not done. `pending` is a file the AI stage never reached, `processing` is one a run was still holding when it ended, and both are `scope_incomplete`. Treating only `pending` as unfinished let a record abandoned mid-flight read as a finished one. A status the enum does not have, or none at all, is not a state to interpret: the adapter cannot say whether the file was finished, so the run is `partial` with `invalid_record_status` rather than guessing in the direction that earns credit.

**A limited run is `partial`, not `success`.** `limit` is a cost bound, so the AI stage investigates that many files and leaves the rest of the scan's candidates `pending` — a real run investigated 6 of 35. No model reached a verdict on those files, so the absence of a finding on one is not a negative result about it, and the run is not a complete observation of the input it was handed. It is recorded as `partial` with `scope_incomplete` and `bundles_resolved: false`, naming the counts and the `limit` that produced them. A `success` there let the scoring contract treat every assigned control as completed and grant quiet credit for files nothing ever opened, which is the one thing the adapter's own note said the run did not establish.

## Model identity and cost

`model_identity.requested` is the configured model. `resolved` is the model DeepSec recorded on its own `analysisHistory` entries, and only when every session in the run agrees on one; sessions that disagree leave it null with a note naming them. `verification` is `self_reported`, which is the execution record's word for "the scanner told us" — the note says which record it was read from. Nothing here verifies which model the provider actually served.

`usage.cost_usd`, `usage.input_tokens` and `usage.output_tokens` are the per-file shares summed back into batch totals. They are DeepSec's own CLI-reported estimates, never a bill.

## What this adapter actually captures

Nothing is observed as it happens. DeepSec's records and the Claude Code transcripts are read after the run, which is what every cell below rests on.

Each column stands for a set of runs, and the sets are written down here rather than in the test, because a column definition the test owned could be changed on one side alone. Every backticked value in a cell is one value that column covers, and a column covers every combination of them.

| Column | `trace_mode` | `transcripts_found` | `sessions` | `batches_failed` | `imports_clean` | `record_failures` | `findings_lost` | `capture_gap` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| trace off | `"off"` | `0` `2` | `0` `2` | `0` `1` | `true` `false` | `0` `1` | `0` `1` | `true` `false` |
| every transcript | `"metadata"` `"content"` | `2` | `2` | `0` | `true` | `0` | `0` | `false` |
| some transcripts | `"metadata"` `"content"` | `1` | `2` | `0` | `true` | `0` | `0` | `false` |
| import not clean | `"metadata"` `"content"` | `2` | `2` | `0` | `false` | `0` | `0` | `false` |
| no transcript | `"metadata"` `"content"` | `0` | `2` | `0` | `true` `false` | `0` | `0` | `false` |
| a batch failed | `"metadata"` `"content"` | `2` | `2` | `1` `3` | `true` | `0` | `0` | `false` |
| records lost | `"metadata"` `"content"` | `2` | `2` | `0` | `true` | `1` `4` | `0` | `false` |
| findings lost | `"metadata"` `"content"` | `2` | `2` | `0` | `true` | `0` | `1` `2` | `false` |
| capture gap | `"metadata"` `"content"` | `2` | `2` | `0` | `true` | `0` | `0` | `true` |

The columns are a sample, not a partition: they do not cover the whole input space, and reading the matrix as if they did would answer a question it never asked. What holds across the whole space, and is driven across it by the same test, is that `finding_validation` and `finding_filtered` are `unavailable` in every run this adapter can have, and that every category is `unavailable` when `trace_mode` is `"off"`.

| Event type | `capture_status` key | trace off | every transcript | some transcripts | import not clean | no transcript | a batch failed | records lost | findings lost | capture gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `model.request`, `model.response` | `model_requests`, `model_responses` | `unavailable` | `partial` | `partial` | `partial` | `partial` | `partial` | `partial` | `partial` | `partial` |
| `tool.start`, `tool.end` | `tool_calls` | `unavailable` | `complete` | `partial` | `partial` | `unavailable` | `complete` | `complete` | `complete` | `partial` |
| `context.selection` | `context_selection` | `unavailable` | `partial` | `partial` | `partial` | `unavailable` | `partial` | `partial` | `partial` | `partial` |
| `finding.candidate` | `finding_candidate` | `unavailable` | `complete` | `complete` | `complete` | `complete` | `complete` | `partial` | `complete` | `partial` |
| `finding.submitted` | `finding_submitted` | `unavailable` | `complete` | `complete` | `complete` | `complete` | `partial` | `complete` | `partial` | `partial` |
| `finding.validation` | `finding_validation` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` |
| `finding.filtered` | `finding_filtered` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` |

`observer.error` is the tenth event type and has no row because it has no `capture_status` key: it is not a category of scanner behaviour, it is the record saying something could not be captured. This adapter does emit it — once per parse-failure dump DeepSec wrote, and once more wherever the transcript collector reports a refused or truncated read of its own. Observer-side instrumentation loss is reported separately, in the capture state the execution record carries beside the trace.

Why each row says what it says:

- **`model.request`, `model.response`.** **One model call is described once, and never zero times.** When a session's main Claude Code transcript imported at least one model turn, that transcript's per-turn pairs are the record of the call and this adapter emits nothing of its own for it — emitting a summed pair beside them made every call and every token of such a session count twice in any accounting over the trace. *At least one model turn* is the test, not *the import returned*: a transcript the collector could not read comes back as a summary with an error event and no turns, and suppressing the pair on that made the call vanish from the trace entirely. The reconstructed pair is the *fallback*, for a session with no usable transcript, where it is the only description there will be: one pair per group, `attempt` 1, `transcript_imported: false`, `usage_available: true`, `cost_usd_cli_reported` carrying DeepSec's estimate, `duration_ms` the batch wall clock and `duration_api_ms` the summed share. DeepSec's totals reach the execution record's `usage` either way, so a suppressed pair loses nothing. The SDK's own retries happen below anything this adapter can see, so `retries_observable` is false and a reconstructed pair can stand for several real attempts: never better than `partial`.
- **Nothing that is not an attempt is shaped like one.** A parse-failure dump is DeepSec failing to read its own agent's output, and it is an `observer.error` (`error_code: agent_output_parse_failure`, `capture_status: unavailable`, no `call_id`), not a response with no request that a reader would count as an attempt. An agent refusal is a fact about the call that *did* happen, so it rides on that call's own response as `metadata.refusals: [{file_path, reason_code, summary}]` — see the reason rule below — and when a transcript described the call instead, the refusal is named in the run's notes rather than given an invented second response to hang on. Every `model.response` in a DeepSec trace pairs with a `model.request` carrying the same `attempt_id`.
- **A refusal reason is model prose, so metadata carries none of it.** `metadata.refusals` holds `file_path` and `reason_code` and nothing else. `reason_code` is a closed value read off the report's *structure* (`refused`, or `refused_with_skipped_files` when it lists what it skipped) and never from classifying the text. A clipped 120-character prefix of the reason used to sit beside it; that was still model prose, and a window that size can open mid-way through a line of source the model was quoting, so it is gone rather than narrowed. The reason itself goes in `content`, which the observer stores in content mode and drops in metadata mode, with every absolute path in it relocated against the workspace first — a home directory may not appear in an event in any mode.
- **A call this adapter could not correlate says so.** Grouping is by `agentSessionId`. An analysis entry carrying none becomes its own group keyed `uncorrelated/<file>/<index>`, never merged with the other entries that carry none, and its events carry `correlation: "missing_session_id"`. Merging them added the paths, turns, cost and tokens of unrelated batches together at exactly the moment the scanner had failed to record a call boundary.
- **`tool.start`, `tool.end`.** Only from the Claude Code transcripts the agent sessions left behind, imported by `scaneval.collectors.claude_code`. A transcript that exists is not a transcript that was read: the collector reports an unreadable one by *returning* a summary that carries an error event and no turns, rather than raising, so this adapter counts a session only when its import captured a turn, a tool call or a span. `complete` then needs every session captured, every import clean — no malformed line, no unmatched tool result, no capture key the importer marked unavailable, no note about a refused or truncated read, and a main transcript that produced at least one model turn — and no observer gap. Anything captured but not all of it is `partial`. Nothing captured is `unavailable`, and so is a run whose transcript collector is not installed.
- **`context.selection`.** Derived entirely from tool results in those transcripts, which is why it can never be better than `partial`: a `Read` result says what text arrived, not what the agent decided to ask for. A run with no imported transcript records none.
- **`finding.candidate`.** `complete` only when every FileRecord was read: the candidates are the whole population of what `scan` recorded, so a record this run could not read is a hole in exactly that population and makes the category `partial`. The candidate id is `<file>#<vulnSlug>#<first line>`, which names a *site* rather than a matcher hit: several of DeepSec's regexes routinely fire at the same file, class and line, so hits that share an id are merged into one event whose `matched_patterns` and `matcher_hits` say how many agreed. Emitting one event each would put two events carrying the same `candidate_id` and different metadata into one trace, which is a link nobody can follow.
- **`finding.submitted`.** One per exported finding, `candidate_id` and `claim_id` both the finding id, `candidate_ids` naming the regex candidates on the same file whose lines overlap the finding's. `complete` only when no batch failed *and* no exported finding was lost on import: a file left in `error`, a parse-failure dump, or a refusal means part of the input reached no verdict, and a finding DeepSec exported that ScanEval could not read is one the trace does not hold.
- **`finding.validation`, `finding.filtered`.** Permanently `unavailable`, for the reason at the top of this document: the agent decides inside its session and DeepSec records only the outputs.

**No category claims completeness over a hole the same run reported.** `capture_status` reads the FileRecords this run could not read, the exported findings that did not become claims, and the observer's own capture state, and any of them downgrades the categories they touch to `partial`. An execution record that said `complete` on one line while its trace record admitted a dropped event on the next was answering one question twice.

Every path in every event is workspace-relative or `external:<basename>`, with `metadata.external_paths` counting the externals. The path comes from where DeepSec *put* a record, not from the record's own `filePath`, which is scanner-written text: publishing that verbatim would have put the run's workspace, and with it the operator's home, into a trace.

Read an `unavailable` as "this cannot be seen", never as "this did not happen".

Two things happen to these values after this function returns them, and neither is this table's to promise. In `metadata` recording mode the emitter downgrades any individual event's own `capture_status` from `complete` to `partial`, because metadata mode stores less than content mode does; the run-level matrix above is about what the adapter could observe and does not change with the mode. And `scaneval.execution` rewrites every value here that claims an observation to `unavailable` when the bundle it lands in holds no counted trace event.

## Running the pilot configuration

`corpus/pilot/run-deepsec.json` is the frozen run. It points `deepsec_root` at `~/Documents/GitHub/sec-test-repos/.deepsec` with a leading `~`, so it expands to whatever operator runs it; point it at your own workspace.

```
.venv/bin/scaneval validate run-config corpus/pilot/run-deepsec.json
.venv/bin/scaneval run corpus/pilot/run-deepsec.json --out results/pilot-deepsec
```

It is a pipeline exercise, not a model comparison: `claude-haiku-4-5` at `thinking_level: low`, `limit: 6`, `batch_size: 3`, `concurrency: 1`. That bounds a run to two agent batches over six files per input. `trace_mode: content` keeps the traces local, because they carry the source that was sent to the model.

**Expect every invocation of this run to be `partial` with `scope_incomplete`.** `limit: 6` is the whole point of the configuration and it leaves most of each repository scanned but never investigated. That is the honest status for it: a complete observation of one of these inputs needs a `limit` that covers the input.

## Limits

- Nothing here is a live observation. A DeepSec run that crashed before writing a record leaves this adapter nothing to read, and the absence of a record is not evidence the work did not happen.
- The transcript join is by `agentSessionId`, so a session whose transcript the operator has deleted, or that ran under a different `~/.claude` home, imports nothing and is counted honestly as a session without a transcript.
- A finding whose `(filePath, title)` pair does not appear in the file records gets no `native_id`. That happens when the export was filtered or rendered from a state the file records no longer hold.
- The adapter checks that the paths it reads stay inside the directories this run created. That is a check against the obvious escape, not isolation; `docs/THREAT_MODEL.md` states what it does and does not defend against, and it applies here exactly as it applies to the own-harness adapter.
