# Initial evaluation core

This alpha implements step 1 of [the design's build order](DESIGN_DECISIONS.md#10-packaging-deliverables-and-build-order) and the first vertical slice of step 2. It is the supported execution and evaluation path, not the completed benchmark. Package version is `2.0.0a1`.

No benchmark results are published. Every case in the pilot pack carries mechanical checks only, so every plan built from it has draft scope; no matching decision has been approved. The [pilot guide](PILOT.md) explains prerequisites, local execution, and review requirements. It contains no scanner results.

## What works

- Validate eleven versioned JSON contract kinds: scan requests and results, evaluation plans, review decisions, execution records, case packs, review records, run configurations, run manifests, evaluation schedules, and blinding maps.
- Build an evaluator-side case pack: pin snapshots, draft cases from supplied artifacts, run mechanical (L1) checks against an exported tree, record explicit human reviews, admissions, and dispositions.
- Fetch a pinned commit into an immutable source cache and export it to an isolated trial directory with a recorded tree hash and preparation provenance.
- Execute a frozen run configuration: freeze the evaluation schedule before any input exists, prepare every input, record an input that cannot be prepared against that input rather than stopping the run, freeze the pack, invoke each system once per input per repetition, and write one bundle per invocation plus a run manifest.
- Blind selected identity cues in documentation and display metadata with a reviewed per-repository map (the `metadata_blinded` profile), all or nothing, keeping the original export evaluator-side.
- Run three real adapters: pinned Semgrep OSS against a local rules checkout, the own harness through its own engine entry point with the observer wrapped around its default model runner, and the third-party DeepSec scanner run unchanged through its own CLI.
- Draft review decisions by routing claims to planned targets, then record and approve them through explicit human steps.
- Score one saved output against all assigned targets and controls for that input, reporting full-output recall, first-hit ranks, native review-budget recall, exact duplicates, unresolved findings, and conditional control bounds.
- Import the records an agent CLI wrote for itself — Claude Code transcripts and `stream-json`, and `codex exec --json` — into trace events, so a harness that shells out to one becomes observable without being edited.
- Report, from a saved bundle, whether each labeled target's code region was supplied to the model and in which invocation.
- Replay the same saved records without models or network access, and generate a standalone HTML report.
- Import one run of a saved SARIF 2.1.0 log, offline, into a bundle that review, score, replay, and report read unchanged, with an import record accounting for every result; the log's own account of how its tool ran is recorded, not verified ([SARIF import](SARIF_IMPORT.md)).

The core does not determine whether an arbitrary natural-language allegation establishes a root cause. That decision comes from a frozen evaluator-side review record. Replaying that record is deterministic; producing the underlying security label or a live model response is not made deterministic by this package.

## Try it

Requires Python 3.11 or later. Run from the repository:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
scaneval --version
scaneval demo results/diagnostic-demo
```

Open `results/diagnostic-demo/report.html`. The demo is the design's worked example, with fabricated source, findings, and review decisions. It makes no scanner or model calls and supplies no evidence about real-world detection performance.

Expected results:

| Observation | Result |
|---|---|
| Assigned targets | 2 on one input |
| First-hit ranks | T1 at 1, T2 at 5 |
| Recall at 3 claims | 50% |
| Recall at 5 claims and full output | 100% |
| Delivered claims | 5, including 1 exact duplicate |
| Unreviewed distinct claim | 1, not automatically a false positive |
| Capability-safe control | 1 false allegation, even though it ranks below 3 |
| Fixed-target control rate | N/A, none assigned |

All commands refuse to overwrite existing output files. `demo` requires a new directory.

## Contracts

Schemas ship inside [`src/scaneval/schemas`](../src/scaneval/schemas) and are the values `scaneval validate` accepts.

| Kind | What it holds |
|---|---|
| `scan-request` | The sanitized invocation handed to a scanner. Cannot carry target IDs, regions, fixes, or decisions. |
| `scan-result` | Normalized claims with an explicit execution status and ranking mode. |
| `execution-record` | Exit status, timing, tool and model versions, declared policy, per-category capture, and provenance for one invocation. |
| `evaluation-plan` | Assigned targets and controls for one materialized input, its scope, review budgets, and pack provenance. |
| `review-decisions` | Per-claim matching decisions and per-control assessments, bound to a saved result by hash. |
| `review-record` | Who produced a decisions file, its state, and the hashes it binds to. |
| `case-pack` | Snapshots, cases, evidence, controls, check results, reviews, and admissions. |
| `run-config` | A frozen run: pack, inputs, systems, repetitions, timeout, trace mode, network policy. |
| `run-manifest` | What ran, what was skipped, where every artifact landed, and each input's preparation outcome. |
| `evaluation-schedule` | Every assignment, each input's pre-registered plan, and the vulnerable/fixed pairs of one run, frozen before any input is prepared. |
| `blinding-map` | A reviewed per-repository replacement map for the `metadata_blinded` profile: pseudonyms, pinned variants, per-file edits with the hashes and counts they expect, and a chained review history. |

A run configuration is read at 2.0 or 2.1, and every run writes a 2.1 manifest and a 2.1 schedule. A standard input named as its own snapshot keeps the 2.0 plan and 2.0 execution record it always had; a renamed or blinded input plans at 2.1, and a blinded input's execution record is 2.1 as well. The two new kinds exist only at 2.1.

The preparation record written beside an exported tree (`provenance.json`) is versioned but has no JSON Schema of its own and is not a contract kind. A standard export writes it at 2.0, exactly as before; a blinded export writes it at 2.1 with the original export and the transformation added.

## Materialization and the immutable cache

`scaneval.materialize` fetches exactly one 40-hex commit into a cache directory (default `.repos`) keyed by repository and short SHA. A cache entry that already exists is verified rather than refetched: its HEAD must be the requested commit and it must have no local modifications. A branch, tag, or short id is refused.

Export copies the tracked regular files of that commit into `<trial>/source`. `.git`, `.securevibes`, `.scaneval`, and `.repos` are stripped; submodule gitlinks and symbolic links are not exported and are recorded as skipped with a reason. Files a scanner may read as project instructions (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.cursor/`, and similar) stay in the export under the `standard` profile and are recorded as retained identity cues.

The tree hash is the canonical SHA-256 of the `{relative path: file content hash}` map. The `metadata_blinded` profile is described in the next section. Without an approved map that fits the export it is refused, never silently downgraded to `standard`.

An adapter that requires git gets a single synthetic commit with a neutral identity created in the workspace copy. Original history is never exported.

This is preparation and provenance, not a sandbox. Filesystem and network policy are enforced only for a system that runs under the `oci` execution backend (below); for every other system they must be enforced outside this package.

## Metadata blinding

The `metadata_blinded` profile reduces selected identity cues in an exported snapshot: branding, documentation identifiers, and display metadata. It never renames a package, module, import, source identifier, or path, and never changes a dependency, executable logic, or build, CI, or security configuration. Package names and recognizable code can still reveal the repository, so it is partial blinding, not anonymization and not a defence against memorization.

A blinding map (`blinding-map`) is evaluator-side and never enters a scanner workspace. One map covers every blinded snapshot of one repository, so a vulnerable and a fixed snapshot carry the same pseudonyms. It holds:

- **Pseudonyms**, each an original token and its replacement. Neither side may be blank or hold a line break, originals and replacements are unique, and, ignoring case, no replacement contains an original and no original contains another pseudonym's replacement.
- **Variants**, the snapshots it covers, each pinned by commit and by the tree hash of its original export.
- **Edits**, one file each, with a role (`documentation_identifier`, `non_runtime_branding`, or `display_metadata`), a stated rationale, the originals replaced there, and for every variant either the exact file hash and the occurrence count of each original or that the file is absent. A `display_metadata` edit also states its `role_check`: why the field is not read at runtime.
- **Reviews**, a chain whose end the map records. Each review binds the map's content digest, which is the map without its reviews.

A map is applied only while its latest review approves the content as it stands. An unreviewed map, one whose latest review rejected it or reopened it (`unresolved`), and one edited after its latest approval are refused. The reviewer name is the caller's; the tool never supplies one, and a review records a claim of review, not a signature.

Which files an edit may touch is decided from the path. Documentation (`.md`, `.markdown`, `.rst`, `.txt`, `.adoc`, `.asciidoc`, `.org`) may be edited under any role, and `.yml`, `.yaml`, `.toml`, `.json`, `.cfg`, and `.ini` only as `display_metadata` with a role check. Refused whatever the suffix: license, attribution, and security files (`LICENSE*`, `NOTICE*`, `AUTHORS*`, `SECURITY*`, and the like), dependency manifests and lockfiles, build, CI, and security configuration, anything under `.github/workflows/`, `.github/actions/`, `.circleci/`, or `.git/`, and the files a scanner reads as instructions, such as `CLAUDE.md`. Every other file, source and scripts included, is never edited, and neither is a file with no suffix such as `README`. The path rule is a guard; that a field is not read at runtime is the reviewer's stated judgment.

Application is all or nothing. The original is exported to `<trial>/original/source`, and every check runs before the transformed tree exists: approval; the repository; the variant's commit and tree hash (otherwise the map is stale); each edit's path class; each expected file's presence or absence and exact hash; strict UTF-8; every occurrence of every original, refusing an original that overlaps itself or another (ambiguous or overlapping matches); the reviewed occurrence counts; and that no replacement forms an original again with the text beside it. Only then is the export copied to `<trial>/source` and the reviewed occurrences replaced. The result is verified rather than assumed: every file no edit names is byte-identical to the original, every file keeps its mode, and line *n* of an edited file is line *n* of the original with the reviewed tokens replaced. Claim locations therefore map to the original export as the identity, which is why labels written against the original score a blinded input.

The 2.1 preparation record describes the transformed tree in its standard fields and adds `original` (the original export's tree hash, file count, and byte count) and `blinding`: the map id, version, and digest, the approving reviewers, both tree hashes, every edit with the lines it changed, its occurrence counts, and both file hashes, every check that passed, the identity cues that remain, and the location remapping (`identity` for lines and paths). Remaining cues are every original still found anywhere in the tree, counted ignoring ASCII case, with up to 50 files by count, and the instruction files, which blinding never edits.

In a run, a blinded input needs a 2.1 configuration naming its map. Refused before the output directory exists: a map that cannot be loaded or does not validate, a blinded input of a 2.0 configuration, blinded inputs of one repository that name different maps (another id or another content digest), and a run id, or a system id, model id, model revision, or configuration, that names an original, ignoring case, because each of those reaches the scan. A map that is not approved or does not fit the export is that input's preparation failure. The snapshot's declared tree hash and the mechanical checks are asked of the original export, because that is what the labels describe; the request, the result, the plan's input hash, and the execution record bind to the transformed tree, and the plan and the 2.1 execution record name the map. A scanner is handed a copy of the transformed `source` only: never the map, `provenance.json`, the original export, or anything under `evaluator/`. The schedule names each blinded input's map, and pairs blinded inputs only with each other.

`scaneval blinding check MAP --pack PACK` fetches and exports each variant into a temporary directory and applies the map exactly as a run would, reporting approval instead of requiring it, so a curator can check a draft before anyone reviews it. It prints each edit's counts and changed lines, the checks that passed, and the files that still carry an original, and it exits 1 when the map is not approved or any variant refuses it. It never writes the map. `scaneval blinding review MAP --reviewer --role --decision --note` appends one chained review and replaces the map through a temporary file, as a pack is replaced.

It does not discover identity cues, parse source, or decide whether a field is read at runtime. The leak check is a substring test of the declared originals, so a spelling the map does not declare, such as a hyphenated product name, is not caught. Replacement is exact and case-sensitive, so each spelling to replace is its own pseudonym. The map itself is not copied into the run directory; the run records its identity and digest.

## The invocation runner and the bundle layout

`scaneval run <config> --output <new dir>` executes a frozen run configuration and writes:

```text
<out>/
  run-config.json          canonical copy of the configuration that was executed
  run-manifest.json        what ran, what was skipped, and where every artifact landed
  evaluator/schedule.json  every assignment, pre-registered plan, and pair, written before any input
  evaluator/pack.json      the pack copy this run froze, with its mechanical check results
  inputs/<input id>/       exported source tree plus preparation provenance beside it
  invocations/<id>/        one bundle per input, system, and repetition
```

An input is named by its input id: a 2.0 configuration's snapshot id, or a 2.1 configuration's `input_id`, which defaults to the snapshot id with `.blinded` appended for a blinded input. Invocation ids are `<input id>__<system id>__r<repetition>`. A blinded input's directory also keeps the original export under `original/source`, evaluator-side.

Each invocation bundle holds:

```text
<invocation_id>/
  request.json             sanitized scan request, no labels
  result.json              normalized claims with explicit status
  execution.json           exit status, timing, versions, policy, capture, provenance
  raw/                     stdout, stderr, native artifacts, captured harness state
  trace/                   observer events when the adapter captured any
  evaluator/plan.json      targets and controls planned for this input
  evaluator/decisions.json machine-drafted decisions, every one unresolved
  evaluator/review-record.json  state and binding hashes for those decisions
  evaluation.json          computed result and input-record hashes
  report.html              local report
```

A scanner only ever sees a private workspace copy of one export. `raw/` and `trace/` are staged inside that workspace and moved into the bundle once the scan returns or raises, so no path handed to an adapter resolves inside the run directory. The source is hashed before and after the scan and `source_modified` records the comparison. An invocation that fails, times out, or hits an unsupported language keeps that status; it is never rewritten as an empty successful scan.

An input that cannot be prepared (a failed fetch or export, a declared tree hash the export contradicts, a blinding map that is not approved or does not fit) is recorded against that input. Its manifest row carries the failure's type and message, each of its assignments is a skipped invocation naming it, no adapter is called for it, and the other inputs still run. A run whose every input failed still completes, and `scaneval run` exits 1 for it. Any other failure once the output directory exists, an interrupt included, writes a manifest with status `failed` before the exception leaves the runner.

### The evaluation schedule

`evaluator/schedule.json` is written once, after `run-config.json` and before the first input is fetched, so nothing the run observes changes what it was assigned. It lists every assignment of a system to an input and a repetition under the invocation id its bundle will carry, including the assignments of an input that will fail preparation and of a system that will be skipped, so a failure cannot drop out of a denominator. Each input records the plan the pack gives it before execution, built from the tree hash its snapshot already declares, with each target's case, canonical id, kind, variant family, workload, component role, project, and level. A snapshot that declares no tree hash, or a pack that refuses to plan it, is recorded as `unavailable` with the reason, and that input's plan is first built when it runs. Vulnerable/fixed pairs are matched in advance: a target planned on one full-scan input with a fixed-target control of it planned on another full-scan input of the same profile, repetition by repetition. Systems record a digest of their configuration, their network policy, and the execution backend they declare.

The schedule is a function of the configuration, the pack as supplied, and its creation time, and the manifest names it in `schedule_path`. It holds no outcome, and nothing reads it to aggregate yet.

The declared network policy is recorded, and enforced only for a system that runs under the `oci` execution backend. The runner computes single-invocation numbers only: no corpus weighting, repeated-run uncertainty, cross-system comparison, or promotion gate is computed anywhere.

## Execution backends

A system runs under the `local` backend unless its entry in a 2.1 run configuration selects another:

```json
{"system_id": "semgrep-oci", "adapter": "semgrep", "config": {"ruleset": {"url": "...", "commit": "...", "paths": ["python"]}},
 "execution": {"backend": "oci", "image": "semgrep/semgrep:1.177.0@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198"}}
```

`local` runs the scanner as the operator and records `isolation.enforced: false`. `oci` runs every scanner process in its own Docker container, created for that command and removed after it: read-only root filesystem, no capabilities, `no-new-privileges`, a non-root user, pids, memory, CPU, and file limits, a size-limited `noexec` `/tmp`, only the workspace, raw-output, and pinned-checkout mounts, and the network policy enforced. `none` means no network. `model_provider_only` needs `egress` (the exact host and port pairs) and a digest-pinned `proxy_image` that provides `python3`; the scanner then reaches only those pairs, through a CONNECT proxy that logs every decision. `unrestricted` is recorded as not enforced. Optional `limits`, `user`, and `credentials` (environment variable names, passed by name and never recorded) complete the block. Images are never pulled: `docker pull` the pinned reference first.

Only an adapter declaring `oci_compatible` runs under `oci`. `semgrep` does, and uses the image's own `semgrep`. `llm-harness` and `deepsec` are refused, and the refusal is recorded as the system's skip reason. A preflight that fails, such as an unreachable engine, a missing image, a mount the daemon cannot see, or a scan network the engine did not isolate, is recorded as a failed invocation. A system is never run locally in its place. The daemon must see the workspace, so under Colima, which shares only the home directory, give the run a `--workspace-root` inside the home directory and keep the source cache there too. Each such execution record is 2.1 and carries an `isolation` block: the engine, the image identity, every setting, the mounts, the network, and each container's outcome. [The threat model](THREAT_MODEL.md) states what the backend guarantees and what it does not. Replay needs neither Docker nor the network.

## Adapters

Three adapters are registered: `semgrep`, `llm-harness`, and `deepsec`. An adapter runs the real product once, preserves its raw output, and translates native findings into normalized claims. It never receives labels and never decides whether a claim is true.

**`semgrep`** runs Semgrep OSS against a local git checkout of a rules repository pinned to one commit, with `--metrics=off` and no registry download; both its version probe and its scan pass `--disable-version-check`, so neither asks the network for a newer release. A `p/...` or `r/...` registry config is refused because it is not a pin. Preparation records the ruleset commit, the number of rule files Semgrep's own `--config <directory>` walk would select, and one aggregate hash over those files; a symlink anywhere under a configured ruleset directory is refused rather than followed. Native rule identity is recorded relative to the pinned checkout so the cache path does not leak into the rule id. A run that scanned no paths and reported nothing is an error, not a quiet negative result.

**`llm-harness`** runs the `securevibes-agent` and `fieldglass` engine family through its own engine entry point inside its own `tsx`. Presets exist for both; only `securevibes-agent` has been exercised against a live model. ScanEval injects only the harness's default model runner wrapped by the observer, a progress reporter, and — when the harness build exports one — an engine observer the harness already has a place for. Nothing else about the scan is supplied or altered. Findings are imported from the harness's own `findings/*.md` records; they are file-level, and this importer keeps them file-level and never invents line ranges. The harness plan, threat model, scan log, profile, and specialist records are copied into the staging directory so they survive as hashed raw artifacts, and the whole state directory is captured separately. Only `bootstrap` mode on a full scan is supported; native PR mode is not wired.

**`deepsec`** runs the third-party DeepSec CLI (`vercel-labs/deepsec`, pinned at 2.3.10) unchanged: `scan` for its regex candidates, `process` for its Claude Agent SDK investigation, `export` for the findings. No DeepSec code is modified, wrapped, or injected into, and nothing is written into the installed workspace. Because DeepSec resolves its configuration from the working directory, the adapter builds a private workspace inside the run's own raw output at `raw/deepsec-workspace/`, with one project, no plugins, and a symbolic link to the installed `node_modules`; everything DeepSec writes lands there and is captured. Events are reconstructed afterwards from DeepSec's own file records and from the Claude Code transcripts its agent sessions left behind, so every one of them carries `source: harness_record` or the transcript importer's own source, never a claim to have watched the scan happen.

**Native PR review (`semgrep` and `deepsec`).** A request whose `input.mode` is `pr` names two commits, `base` and `head`, of a two-commit history in the scanner's workspace, with `HEAD` at `head` and a clean status. An adapter declares that it reads one by listing `pr` in `scan_modes`, and refuses before anything runs a mode it does not implement, a full request that carries `pr`, a `pr` that is not two full commit ids, and a workspace that does not hold that history, which the evaluator checks with git ahead of the scanner. So a PR request is never quietly run as a full scan.

- `semgrep` adds `--baseline-commit=<base>` to the full-scan argv. Semgrep's own diff scan then reads only the files the change touched and drops the findings its own comparison matches to the base commit; the adapter compares nothing itself. Semgrep resets the workspace tree to the base commit and restores it in place, so the source must be writable, and under the `oci` backend, which mounts it read-only, a PR request is answered `unsupported` with the reason recorded and nothing runs. A change that touches only deleted paths and files no rule applies to (documentation, say) makes the diff scan read nothing and report nothing. That is a success with an "Empty baseline review" note only when Semgrep exited 0 with no diagnostic, no result was lost in the import, and git shows no changed path with the extension of a supported language; anything else stays the `nothing_scanned` error. The extension test is the adapter's own approximation, not Semgrep's target selection, and it errs toward the error. Semgrep 1.177 also drops a head finding whose file failed its baseline scan and records that only as a diagnostic, so the result counts such diagnostics in a note.
- `deepsec` skips the `scan` step and runs `process --diff <base>..<head>`, DeepSec's direct mode, then `export`. DeepSec lists the changed files itself (added, modified, renamed, or copied, never a deletion), drops any that match its default ignore filter, scans just those, and investigates each; the changed paths it dropped are named in a note, as DeepSec's own scope and not a failure. `--limit` has no effect in direct mode, so it is not sent and a note says so. Direct mode exits 1 for findings, for an errored batch, for an exhausted quota, and also for a runtime failure, so the run goes on to export and reads what the exit meant from DeepSec's own records: findings are a normal review, files left in `error` or unfinished make it `partial` (`error` when no file reached a verdict), an exhausted quota is `quota_exhausted`, and an exit 1 that no record explains is an error. What DeepSec printed only names the reason and never decides the status. "Nothing to process" is a completed empty review only with exit 0, no file record, and DeepSec's own sentence; the same silence without it is an error. A PR run reports the same capture categories as a full run. It has been tested against a fake CLI that prints what 2.3.10 prints, and has not run against a live model.

## Observer connection: what is captured and what is not

The TypeScript observer is connected to the own harness through [`llm_harness_driver.mts`](../src/scaneval/adapters/llm_harness_driver.mts), driver version `2.2.0`. Importing the SDK still captures nothing on its own; this driver is what emits.

What the driver can see is a property of the harness build as much as of this adapter, and it never assumes. It feature-detects two optional surfaces the harness may export — the runner hooks (`PI_RUNNER_HOOKS_VERSION`) and the engine observer (`HARNESS_OBSERVER_VERSION`) — records which of them it found as `hooks` in its own output, and falls back independently for each one it does not find. A checkout exporting neither is observed exactly as it was before either existed: one `model.request`/`model.response` pair per logical call, `context.selection` from the harness's own progress notes, and `finding.submitted` from the returned summary. That fallback is what keeps an unpatched harness checkout working.

Against a build that exports them, the driver additionally records:

- one model request/response pair per **CLI attempt**, from inside the harness's own retry loop, so a retry is an observation rather than something folded into one event; the attempt number, the maximum, the retry decision and its backoff ride along, and each attempt joins its call by `call_id` with an `attempt_id` of `<call_id>/attempt-<n>`;
- on the claude route, the CLI's own token counts, its cost estimate, the turn count, the session id and the served model id, because the driver asks that route for `--output-format json` while the engine still receives exactly the text a text-mode run would have printed;
- `context.selection` as the engine's own report of what it placed in each prompt: every span's path, line range, character count, the sha256 of exactly the text supplied, the role it played, and whether that text could be located in the file;
- `finding.candidate` and `finding.filtered` under the engine's own candidate ids, alongside the submitted records.

Three limits survive both surfaces, and one category changes meaning rather than becoming visible:

- **Tool dispatch stays unobserved on the claude route.** It happens inside the model CLI subprocess this driver spawns but cannot see into, and that route runs with session persistence off, so no session transcript is left behind for the collectors to read either. No tool event is emitted, and that establishes nothing about whether a tool ran. Only the mock runner, which spawns no process at all, makes the concept genuinely inapplicable.
- **Model events stay `partial`.** An attempt is a CLI invocation rather than an API request, so the turns taken inside one attempt are not visible from here, and the pi route reports no usage at all.
- **Context selection stays `partial` for the run.** The threat planner's model calls and some specialist invocations are not instrumented, so a model request with no context event beside it is an uninstrumented call, not a call that was given no context.
- **Validation becomes `not_applicable`, not visible.** The validation stage is the consensus judge, the judge runs in pr mode, and this adapter refuses every mode but bootstrap, so no run it can produce has that stage in it. That is a different statement from having one and being unable to see it.

The own-harness capture matrix lives in [the SDK guide](OBSERVER_SDK.md) and is checked against the adapter by tests. DeepSec's capture expectations are maintained as test fixtures. The execution record reports the capture status for each run.

Each route's declared tool policy is recorded as the harness's own declaration, never as an observation. Model identity is recorded as `unverified` when the path that ran does not report the served model. A harness self-estimate of cost is preserved as a self-report and a CLI-reported estimate as an estimate; neither is a measurement and neither is a bill.

`unavailable` is not `not_applicable`, and neither is evidence of absence. Whatever a matrix cell claims, `scaneval.execution` rewrites every value claiming an observation to `unavailable` when the bundle it lands in holds no counted trace event.

## Native CLI collectors

`scaneval.collectors` reads the records an agent CLI wrote for itself and turns them into trace events, so a harness that shells out to Claude Code or Codex becomes observable **without being edited**. It imports Claude Code session transcripts, `claude -p --output-format stream-json --verbose` output, the single `--output-format json` result object, and `codex exec --json`. Nothing there spawns a process, patches a client, or makes a network call: the importers are readers over text handed to them, and only the transcript finder touches the filesystem.

A collector is a reader, not a wrapper, and that is the limit as well as the point. It sees what the CLI chose to write down, so every event says where it was read from and carries `partial` capture wherever the reading was derived rather than observed. Retries a CLI made internally are invisible; a file read through a shell command is never a span, which is why Codex reports no context selection at all; a subagent transcript carries the delivered text with no path or line range, so it produces no spans. [The collectors guide](COLLECTORS.md) states each limit against the fixture that demonstrates it.

The fixtures under `schema/v2/fixtures/collectors/` are real CLI runs against a two-file synthetic workspace, scrubbed by [`scripts/sanitize_native_trace.py`](../scripts/sanitize_native_trace.py). That script is an allowlist rather than a search-and-replace — the record types the collectors read are rewritten field by field and every other record is reduced to a stub — and it audits its own output, refusing to write a file in which a home path, an unscrubbed workspace path, or an email address survived. One fixture, `claude-code-edge-cases.jsonl`, is hand-built in the same record shape for branches a short successful run cannot produce.

## Diagnostics

`scaneval diagnose context-coverage <bundle>` answers one question about a saved run: for each labeled target, was the target's code region delivered to the model, and in which invocation. When a scan misses a known vulnerability, "the model was never shown the code" and "the model was shown the code and said nothing" look identical in the result, and only the second is a detection failure.

It joins the pack's `accepted_locations` to the trace's `context.selection` spans — evaluator-side, after the run, so nothing a scanner saw could have been affected by it — and classifies each target per invocation as `included`, `partial`, `absent` or `unknown`. Spans live in `metadata`, so it works in `metadata` trace mode as well as `content` mode, and it reads no file content.

It scores nothing and writes nothing into the bundle. `included` says the lines were delivered, not that the model attended to them or that what was delivered was sufficient. Partial capture turns `absent` into `unknown` and never the other way round, because an absent event is never evidence of absent activity. A target whose code was never supplied is still a target the scan did not detect: this explains a miss, it does not excuse one. [The diagnostics guide](DIAGNOSTICS.md) carries the classification table, the reason codes, and everything the document declines to claim.

## Case packs, mechanical checks, and explicit human approval

A pack is evaluator-side data and is never copied into a scanner workspace. Code can create drafts and run mechanical (L1) checks; only a recorded human review can raise a case beyond that.

Six checks run against one exported tree, per snapshot: `locations_exist_in_snapshot`, `line_ranges_within_files`, `aliases_well_formed`, `represents_statement`, `evidence_recorded`, and `snapshot_hash_recorded`. They compare declared paths against an exact listing of the export and read file bytes only to count lines. Nothing here parses source, establishes a root cause, or approves anything, so no check raises a case past L1.

Review states are `draft`, `mechanically_checked` (the L1 state), and `human_approved`, which carries whatever level the recorded review named. L3 and L4 additionally require an `independent_reviewer` decision and a `validate` disposition. A case becomes `mechanically_checked` only once every snapshot it references has a recorded passing check set. A referenced snapshot that fails, or that was never checked, demotes a mechanically checked case back to draft. For an approved case the same situation records `validation.checks_failed` and leaves the review state and level untouched, because code never withdraws a human review; plan generation then keeps that case out with a note.

`corpus approve` records the reviewer name the caller supplies and nothing else. Nothing infers approval from a passing check, a matching hash, or the absence of an objection. A license is never recorded as verified by the CLI. An imported artifact becomes a draft case with a `needs_evidence` disposition, never a label.

Plan generation degrades to the lowest state present: a plan is `reviewed` only when every included case is `human_approved` at L3 or L4, and `draft` otherwise. Planned items keep their real validation level; the scope, not a rewritten level, says whether the labels are reviewed.

## Review workflow

`scaneval review init` routes saved claims to planned targets. A candidate means only that the claim's primary location path is an accepted location path of that target. Routing does not read claim prose, compare line ranges, weigh severities, or establish a root cause. Every decision it writes is `unresolved`, so a draft can never earn detection credit, a rejection, or a quiet control, and an empty draft is not evidence of absence.

A human edits `evaluator/decisions.json`. `review record` then re-drafts the review record for the edited decisions and keeps the recorded review history. `review approve` records one explicit human approval, refusing decisions that no longer bind to the saved result.

`review status` reports `missing`, `stale`, `draft`, or `human_approved`. `stale` means the decisions file or the plan changed after the record was written, or that the record and the decisions name different runs. That is the only tampering it can see: it does not check the result, the source tree, or the pack the plan came from. A `human_approved` state is the record's own assertion, not a verified one, and it is not a signature or proof that the named reviewer read anything.

`replay` prints a warning on stderr for any bundle whose review state is not `human_approved`, and `report` prints one for a draft, stale, or missing record. The HTML report carries the same statement in its own notice.

## Run configuration

A run configuration is a frozen document naming the pack, the inputs, the systems, the repetition count, the timeout, the trace mode, and the network policy. The three pilot configurations are [`corpus/pilot/run-semgrep.json`](../corpus/pilot/run-semgrep.json), [`corpus/pilot/run-harness.json`](../corpus/pilot/run-harness.json), and [`corpus/pilot/run-deepsec.json`](../corpus/pilot/run-deepsec.json). The DeepSec one names an installed DeepSec workspace with a leading `~`, so it expands to whichever operator runs it rather than pinning one machine.

A 2.1 configuration can also name each input with `input_id` (its directory and invocation name, never shown to a scanner), choose its `profile`, name the reviewed `blinding_map` of a `metadata_blinded` input by a path relative to the configuration, and give a system an `execution` backend (`local`, or `oci` as described in the [threat model](THREAT_MODEL.md)). A native PR input (`mode: pr`) is refused when the configuration is read: this build cannot prepare one, and a full scan of the head never stands in for it.

`--only-input` (input ids) and `--only-system` narrow a run. Naming something the configuration does not contain is an error rather than a silently empty run, and what was narrowed away is recorded in the manifest and the schedule. `--workspace-root` chooses where the scanner's private workspace is created; a workspace inside the run output, the source cache, or an exported input is refused. Under the `oci` backend it must be a directory the Docker daemon can see.

## CLI surface

| Command | What it does | Network or model calls |
|---|---|---|
| `validate <kind> <path>` | Validate one of the eleven contract kinds. | none |
| `score --plan --result --decisions` | Score separately stored records. | none |
| `replay <bundle>` | Recompute a saved bundle offline. | none |
| `report <bundle> --output` | Score a bundle and render standalone HTML. | none |
| `demo <new dir>` | Create the fabricated conformance bundle. | none |
| `corpus init` | Create a new draft pack file. | none |
| `corpus add-snapshot` | Pin one repository commit; license stays unverified. | none |
| `corpus import` | Draft one case from a fix commit, finding, or document. | none |
| `corpus validate <pack>` | Print a pack summary. | none |
| `corpus validate <pack> --snapshot-id` | Fetch and export that snapshot, run the L1 checks, record them. | fetches the pinned commit |
| `corpus approve` | Record one explicit human review of a case. | none |
| `corpus admit` | Record an admission decision. | none |
| `corpus disposition` | Record a screening disposition and its stated reason. | none |
| `plan --pack --snapshot-id --tree-hash --output` | Build one evaluation plan for a materialized input. | none |
| `review init <bundle> --pack` | Route claims to targets as unresolved candidates. | none |
| `review record <bundle>` | Re-draft the review record after a human edited the decisions. | none |
| `review approve <bundle> --reviewer --note` | Record one explicit human approval. | none |
| `review status <bundle>` | Report missing, stale, draft, or human_approved. | none |
| `blinding check <map> --pack` | Apply a blinding map to each variant in a temporary directory and report the result. Writes nothing to the map. | fetches the pinned commits |
| `blinding review <map> --reviewer --role --decision --note` | Record one named review of a blinding map. | none |
| `run <config> --output <new dir>` | Execute one frozen run configuration. | depends on the configured systems |
| `import sarif <log> --pack --snapshot-id --tree-hash --system-id --output` | Import one run of a saved SARIF 2.1.0 log into a new bundle; nothing the log names is fetched or opened. | none |
| `diagnose context-coverage <bundle>` | Report whether each labeled target's code was supplied to the model. Writes nothing into the bundle. | none |

Exit codes: `2` means the command could not be carried out (a usage or contract error, a refused overwrite, a failed fetch or export, a SARIF log refused whole). `1` means it ran and reports a negative result (a mechanical check set failed, a run could not prepare some input or produced no usable scan from some system, an imported SARIF log holds none, or a blinding map is not approved or a variant refused it). `0` means it ran and reports nothing wrong, which is not a statement that any label or decision is correct.

No command writes inside a materialized trial directory, and every output path except a pack file, a blinding map, and a review record is create-only.

## Bundle and replay

```text
diagnostic-demo/
  scan-input/app.py          source only
  request.json              sanitized invocation contract
  result.json               saved normalized output
  evaluator/plan.json        assigned targets, controls, budgets
  evaluator/decisions.json   frozen matching and control reviews
  evaluation.json           computed result and input-record hashes
  report.html               local report
  README.txt                fixture limitations
```

```sh
scaneval validate scan-request results/diagnostic-demo/request.json
scaneval validate scan-result results/diagnostic-demo/result.json
scaneval replay results/diagnostic-demo --output results/diagnostic-replay.json
scaneval report results/diagnostic-demo --output results/diagnostic-report.html

# The same evaluator also accepts separately stored records.
scaneval score \
  --plan results/diagnostic-demo/evaluator/plan.json \
  --result results/diagnostic-demo/result.json \
  --decisions results/diagnostic-demo/evaluator/decisions.json
```

The original `evaluation.json` and replay JSON are byte-identical for the same package version and saved inputs. Replay verifies IDs, input-hash agreement, and the review's canonical result hash. It records plan and decision hashes in its output. These hashes identify records; they do not authenticate their author or independently verify the source snapshot. The demo hashes a path/content map, not a production git export.

Replay reads `result.json` and `evaluator/` records. It does not execute `request.json`, inspect source, or replay tools. The directory layout illustrates the evaluator boundary but does not enforce access isolation.

The library entry point is:

```python
from scaneval import evaluate

record = evaluate(plan, saved_result, frozen_decisions)
```

This is saved-record evaluation of documents that already exist. The live path is `scaneval run`, which produces those documents from a frozen configuration.

## Contract rules enforced now

Strict parsing rejects duplicate JSON keys, nonfinite numbers, escaping file paths, missing IDs, and malformed references. Unknown extra fields are rejected so extensions need a contract change.

- **Scanner boundary:** `ScanRequest` cannot contain evaluator target IDs, regions, fixes, or matching decisions. This is a shape check, not automatic source sanitization.
- **Locations:** file-only reports stay file-only. A line range is optional; if supplied it must be positive and ordered. Location overlap alone never earns credit.
- **Claims:** one allegation and its evidence per normalized claim. Separately structured bundles must be split by an importer or reviewer before claiming an atomic count. Adapters normalize the output of the system they just ran. `scaneval import sarif` turns each result of a saved SARIF 2.1.0 log into at most one claim and flags a result that may bundle several allegations for recorded review instead of splitting it ([SARIF import](SARIF_IMPORT.md)); a saved native vendor file has no importer.
- **Duplicates:** canonicalize allegation, kind, native rule ID, primary/related locations, and evidence text. Normalize path separators and line endings. Ignore delivery IDs and ranks. Different evidence stays distinct; semantic duplicate review is not implemented yet.
- **Credit:** one claim or exact-duplicate group can hit at most one canonical target. Duplicate copies keep their review positions. Contradictory frozen decisions are rejected.
- **Ranking:** native ranks must be contiguous and follow the submitted array. Unranked output has no native budget score. Its optional random-order expectation is a separate diagnostic and can be affected by duplicate spam.
- **Bundles:** unresolved bundles leave atomic-claim burden and finite-budget metrics pending. Confirmed full-output hits can still count.
- **Execution:** `success`, `partial`, `unsupported`, `error`, and `timeout` remain distinct. Confirmed partial-output hits can count. Failed assignments remain in the denominator. Only successful, resolved, in-scope output can establish a quiet control.
- **Controls:** all claims are eligible for control review, including those below the review budget. Missing assessments remain unresolved. The completed-observation upper bound counts unresolved assessments as false allegations; it is not a confidence interval. `false_allegations` is its completed-only numerator. `observed_false_allegations` also retains explicit reviewed failures from incomplete output, without using incomplete scans in that rate.
- **Unknowns:** unmatched claims are not automatically false positives. This build does not estimate overall precision.
- **Labels:** `diagnostic` plans allow only fixture labels; `reviewed` plans require declared L3/L4 labels; `draft` plans keep each item's real level and say in their scope that the plan as a whole is not reviewed evidence. Checking the field does not verify independent review.
- **Packs:** a pack's self-consistency is checked, never its correctness. A pack that validates is consistent with itself: no check here reads source, a reviewer, or a scanner.
- **Manifests:** an input with a recorded preparation failure has only skipped invocations, each with a reason and no bundle.
- **Schedules:** the assignments are exactly every input under every system for every repetition, each named by its invocation id; a blinding identity appears exactly on blinded inputs; a pair joins a target and a fixed-target control of it on two full-scan inputs of one profile whose plans were frozen before execution.
- **Blinding maps:** the pseudonym rules, one expectation per variant for every edit naming exactly the tokens it replaces, and a review chain with its recorded end. The contract checks a map against itself; approval and the fit to an export are asked when it is applied.

Scores use equal target/control weights within one input. Do not average them as a release score: corpus weighting, repeated-run aggregation, repository clustering, and promotion gates are not implemented. Zero denominators are `null` in JSON and N/A in HTML.

## Observer SDK

See [the SDK guide](OBSERVER_SDK.md) and [event schema](../schema/v2/trace-event.schema.json).

The TypeScript emitter records supplied model/tool events, selected context, and finding lifecycle events: candidate, validation, filtering, and submission. It does not intercept a harness automatically, change its prompts, enforce networking, or inspect hidden reasoning. Recording is off by default. The harness owns its sink and retention policy. The own-harness driver described above is the one integration that exists; the emitter still captures nothing when imported on its own.

Sink or other instrumentation errors create capture gaps without replacing the operation's result or exception. Missing events are not evidence that an operation did not happen. The HTML report currently shows scores, not a trace timeline.

A Python emitter ships alongside it in `scaneval.observer`, and it is what the collectors and the DeepSec adapter write through. Both emitters are held to one parity contract, which [the SDK guide](OBSERVER_SDK.md) states and a test checks.

```sh
cd sdk/typescript
npm ci
npm test
```

## Limits

- **No detection result exists.** Every case carries mechanical checks only, every plan is draft scope, no matching decision has been approved, and confirmed detection is zero. Any recall figure printed today comes from decisions with no recorded human approval.
- **No controls.** The pilot pack defines no negative controls, so control rates are N/A rather than zero, and no fixed-state snapshot has been prepared.
- **Directory separation is not isolation.** Outside the `oci` backend the declared network policy is recorded, not enforced. Path checks refuse the obvious mistake and do not follow bind mounts or hard links. The `oci` backend holds Semgrep only, trusts the engine, its kernel, and the image, and leaves writable mounts without a size bound; see [the threat model](THREAT_MODEL.md).
- **Hashes identify documents.** They do not authenticate an author, verify a source snapshot, or prove that a reviewer read anything.
- **Capture gaps are not absence.** An `unavailable` category establishes nothing about whether the underlying activity happened.
- **Visibility depends on the build that was run, not only on this package.** The own-harness driver sees attempts, token usage, supplied-context spans and the candidate lifecycle only against a harness build that exports the hooks, and falls back for each surface it does not find. Tool dispatch on the claude route is unobserved either way. What a given run could see is recorded per run, not promised here.
- **Nothing a collector or the DeepSec adapter reports was watched as it happened.** Both read records written after the fact, so their events are derived and say so; a record the CLI never wrote is a record nothing can recover.
- **Single-invocation numbers only.** No corpus aggregation, pair aggregation, repeated-run uncertainty, precision sampling, promotion gate, trace viewer, exporter, or multi-model planner is implemented.
- **Metadata blinding is partial.** It edits reviewed documentation and display metadata only; package names, imports, identifiers, paths, and recognizable code stay, and every blinded export counts the cues that remain. It is not anonymization and does not show that a scanner could not recognize the repository.
- **Not implemented at all:** native PR mode through the `llm-harness` adapter, import of saved vendor output other than SARIF 2.1.0, and semantic duplicate review. The collectors import an agent CLI's own trace records, and `import sarif` imports a saved SARIF log; no other scanner findings file produced outside a ScanEval invocation is imported.

## Requirements for a reviewed comparison

- Independently review case labels to L3 and record admission before reporting reviewed-label scores.
- Review routed claims through `scaneval review record` and `scaneval review approve`; a draft match is not a confirmed detection.
- Validate property-specific fixed/safe controls before reporting control rates.
- Declare configurations, repetitions, budgets, and capture limits before comparing systems. Traces explain recorded behavior; they do not replace label or finding review.

The Python core supports request language tags for Python, TypeScript/JavaScript, Go, and Rust. This does not imply equal corpus coverage or live support for every scanner. Inspect/Harbor selection, Jev corpus assistance, and the separate engineering improvement agent remain outside this slice.

The organization-owned pack path is documented separately in [bring your own corpus](BRING_YOUR_OWN_CORPUS.md).

Run the Python regression suite with `python -m pytest -q`. It covers contracts, materialization, execution, the runner, corpus, review, scoring, observers, collectors, and CLI conformance. No real CVEs are silently imported and no paid model evaluations run during these tests.
