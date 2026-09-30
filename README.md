# ScanEval

ScanEval evaluates security scanners on versioned cases and records how instrumented harnesses reach their findings. The evaluator uses structured outputs and recorded review decisions, not an LLM judge.

> Alpha (`2.0.0a1`). No benchmark results are published. The three cases in [the draft pilot](docs/PILOT.md) have mechanical checks only, with no human-approved labels or matching decisions and no controls. Scanner outputs and traces stay local.

## Quick start

Requires Python 3.11+. Live runs also need Git and the configured scanner.

```bash
python -m pip install -e ".[dev]"
scaneval demo results/diagnostic-demo
scaneval replay results/diagnostic-demo --output results/diagnostic-replay.json
# Open results/diagnostic-demo/report.html locally.
```

The demo uses fabricated evaluator fixtures, not a live scanner or admitted CVEs. It exercises scoring without model calls. Output paths must be new.

For a live run, use the [pilot guide](docs/PILOT.md) to configure a scanner, prepare pinned sources, run, and review the output. To supply your own security fixes, findings, or documents, follow [bring your own corpus](docs/BRING_YOUR_OWN_CORPUS.md).

## Evaluation

One scan can cover several targets on the same input. A finding needs an accepted security allegation, not just a matching line and vulnerability category. Unreviewed findings remain unresolved; they are not automatically false positives.

The scorer reports known-target detection, recall within review budgets, and false allegations against assigned fixed/safe controls. Reviewed precision is estimated separately, from a seeded, human-reviewed sample of delivered claims. Unavailable controls do not become a zero false-alarm rate. Errors and incomplete scans remain distinct from successful scans with no findings. Recorded decisions can be replayed offline.

| Command | Purpose |
|---|---|
| `scaneval validate <kind> <path>` | Validate a versioned contract. |
| `scaneval demo <new dir>` | Create the fabricated conformance bundle. No scanner or model runs. |
| `scaneval score --plan --result --decisions` | Score separately stored records. |
| `scaneval replay <bundle>` | Recompute a saved bundle offline. |
| `scaneval report <bundle> --output` | Render a standalone HTML report. |
| `scaneval corpus init\|add-snapshot\|import\|validate\|approve\|admit\|disposition` | Prepare case packs, run mechanical checks, and record explicit reviews and admissions. |
| `scaneval plan --pack --snapshot-id --tree-hash --output` | Build an evaluation plan for one materialized input. |
| `scaneval run <config> --output <new dir>` | Run a frozen configuration and save its artifacts. |
| `scaneval blinding check\|review` | Dry-run a metadata blinding map against its snapshots, and record a named review of it. |
| `scaneval import sarif <log> --pack --snapshot-id --tree-hash --system-id --output` | Import one run of a saved SARIF 2.1.0 log into a new bundle for review, offline. |
| `scaneval review init\|record\|approve\|status` | Prepare and record the review of an invocation bundle. |
| `scaneval diagnose context-coverage <bundle>` | Compare captured context spans with labeled targets. Does not change scores. |
| `scaneval aggregate <run dir>... --output` | Weight every scheduled assignment of saved runs into corpus metrics with cluster-bootstrap intervals. |
| `scaneval compare <run dir>... --baseline --candidate --output` | Compare two systems assigned the same frozen work, with paired intervals. Decides no promotion. |
| `scaneval precision sample\|queue\|record\|estimate` | Sample delivered claims from saved runs, record human reviews, and estimate reviewed precision. Does not change scores. |

Run `scaneval <command> --help` for required arguments. Only `corpus validate --snapshot-id`, `blinding check`, and `run` reach the network; contacts depend on the configured sources and scanners. Exit code `2` means the command could not be carried out, `1` means it ran and reports a negative result, and `0` means it ran and reports nothing wrong. None certifies that a security label is correct.

## Scanners and visibility

The current adapters are `semgrep` with pinned local rules, `llm-harness` for an own-harness integration, and `deepsec` for the third-party scanner. Scanner CLIs are installed separately. The optional `official-adapters` extra installs Semgrep; a reproducible comparison must also pin its version and rules.

The **ScanEval Observer SDK**, available in Python and TypeScript, records model calls, tool use, supplied context, and finding lifecycle events at instrumented boundaries. It is opt-in. Native collectors can import Claude Code and Codex records without claiming to see decisions the harness never exposed. Capture gaps remain explicit; traces cannot prove hidden reasoning or absence of memorization.

For the TypeScript SDK and harness driver:

```bash
npm ci --prefix sdk/typescript
npm run build --prefix sdk/typescript
```

The `llm-harness` adapter needs a local harness checkout and the built SDK. The `deepsec` adapter needs an installed scanner workspace; it runs the scanner in a separate private workspace.

Guides: [Observer SDK](docs/OBSERVER_SDK.md), [native CLI collectors](docs/COLLECTORS.md), [context-coverage diagnostics](docs/DIAGNOSTICS.md).

## Current limits

- Full-scan execution, case packs, source export, review, scoring, replay, and reports are implemented.
- Each run freezes its evaluation schedule (every assignment, pre-registered plan, and vulnerable/fixed pair) before it prepares an input. An input it cannot prepare is recorded with its skipped assignments, and the other inputs still run.
- The `metadata_blinded` profile applies a reviewed per-repository map to documentation and display metadata only. It is partial blinding, not anonymization: package names, source, and paths are unchanged.
- A saved SARIF 2.1.0 log imports offline into a bundle that review, score, and replay read; its execution report is recorded unverified ([SARIF import](docs/SARIF_IMPORT.md)). Other saved vendor formats have no importer.
- Enforced isolation exists for Semgrep only: a system whose 2.1 run configuration selects the `oci` execution backend runs each scanner process in a locked-down Docker container from a digest-pinned image, with its network policy enforced. `llm-harness` and `deepsec` are refused under it. Every other system runs as the operator, unenforced. See [the threat model](docs/THREAT_MODEL.md).
- Corpus aggregation and paired comparison read saved, frozen run directories ([aggregation](docs/AGGREGATION.md)). They compute no reviewed precision and decide no promotion.
- Reviewed precision comes only from people reviewing a seeded probability sample of delivered claims ([precision guide](docs/PRECISION.md)). It is not a repository false-positive rate.
- Native PR mode and promotion gates are not implemented.
- The initial public workload is not selected. The pilot is an integration exercise, not a representative benchmark or scanner comparison.

[Current capabilities](docs/INITIAL_BUILD.md) describes the implementation. [Design decisions](docs/DESIGN_DECISIONS.md) and [evaluation math](docs/EVALUATION_MATH.md) describe the broader contract and planned work.

## Development

```bash
python -m pytest -q
npm test --prefix sdk/typescript
```

Tests use local fixtures and mock model runners. They do not launch paid model evaluations. CI checks Python 3.11 and 3.13, the TypeScript SDK, and demo/replay from an installed wheel.

| Path | Contents |
|---|---|
| `src/scaneval/` | CLI, corpus, runner, evaluator, adapters, collectors, and Python Observer |
| `src/scaneval/schemas/` | Versioned evaluation contracts |
| `sdk/typescript/` | TypeScript Observer SDK |
| `schema/v2/` | Shared trace contract and conformance fixtures |
| `corpus/pilot/` | Draft case pack and frozen run configurations |
| `scripts/sanitize_native_trace.py` | Scrub native records for collector fixtures |
| `tests/` | Contract, scoring, runner, adapter, Observer, and collector tests |
| `docs/` | Public design and usage guides |

Generated runs belong under ignored `results/`; source caches belong under ignored `.repos/`. Do not commit scanner outputs, private findings, credentials, or content traces.

## License

[MIT](LICENSE). Source snapshots and external scanners retain their own licenses.
