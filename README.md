# ScanEval

ScanEval evaluates security scanners on versioned cases and records how instrumented harnesses reach their findings. Scoring uses structured outputs and recorded review decisions. Static corpus labels can be assessed separately through evidence-bound machine review.

> Alpha (`2.0.0a1`). No benchmark results are published. The [selected CVE corpus](corpus/diverse/README.md) contains 50 CVEs from 32 repositories across seven target languages: 9 Critical, 13 High, 20 Medium and 8 Low by the documented published-CVSS policy. Its 48 pinned vulnerable exports have mechanical checks and a separate machine-review workflow for static labels. Selection emphasizes contextual security reasoning; scanner miss rates remain unmeasured. Fixed controls remain unvalidated. Scanner outputs and traces stay local.

## Quick start

Requires Git and Python 3.11+. Live runs also need the configured scanner.
From a terminal on macOS or Linux:

```bash
git clone https://github.com/Har1sh-k/scaneval.git
cd scaneval
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
scaneval demo results/diagnostic-demo
scaneval replay results/diagnostic-demo --output results/diagnostic-replay.json
# Open results/diagnostic-demo/report.html locally.
```

The demo uses fabricated evaluator fixtures, not a live scanner or admitted CVEs. It exercises scoring without model calls. Output paths must be new.

Start with the [CVE corpus](corpus/diverse/README.md) for the 50 curated cases, severity sources, selection rationale and machine review. [Dataset adapters](docs/DATASET_ADAPTERS.md) add separate PR-review and CVE-detection tracks for AACR-Bench, ReviewBench, Martian, OpenSSF, and your own datasets. The [execution guide](docs/INITIAL_BUILD.md#run-configuration) explains scanner configuration and review. To supply your own security fixes, findings, or documents as case packs, follow [bring your own corpus](docs/BRING_YOUR_OWN_CORPUS.md).

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
| `scaneval investigate <run> --output <new-directory>` | Export a local investigation view and JSON with judgments, trace links, capture states, and artifact bindings ([guide](docs/INVESTIGATION.md)). |
| `scaneval corpus init\|add-snapshot\|import\|validate\|approve\|admit\|disposition` | Prepare case packs, run mechanical checks, and record explicit reviews and admissions. |
| `scaneval corpus machine-prepare\|machine-record\|machine-check` | Prepare evidence packets and validate machine judgments of static CVE labels without HITL. |
| `scaneval corpus add-change-set\|pr-scope\|canonical` | Declare a base/head change set, state which targets and controls are scored in its PR review, and group records by canonical root cause. |
| `scaneval plan --pack --snapshot-id --tree-hash --output` | Build an evaluation plan for one materialized input, or with `--mode pr --change-set-id` and the hashes that identify it, the PR plan of a change set. |
| `scaneval run <config> --output <new dir>` | Run a frozen configuration and save its artifacts. |
| `scaneval dataset list\|fetch\|import\|validate\|inspect` | Load a pinned public dataset, native JSON, or an installed Python dataset adapter ([guide](docs/DATASET_ADAPTERS.md)). |
| `scaneval benchmark plan\|run\|judge-packet\|score` | Evaluate imported datasets with existing scanner adapters, frozen schedules, and supplied machine judgments. |
| `scaneval blinding check\|review` | Dry-run a metadata blinding map against its snapshots, and record a named review of it. |
| `scaneval import sarif <log> --pack --snapshot-id --tree-hash --system-id --output` | Import one run of a saved SARIF 2.1.0 log into a new bundle for review, offline. |
| `scaneval review init\|record\|approve\|status` | Prepare and record the review of an invocation bundle. |
| `scaneval diagnose context-coverage <bundle>` | Compare captured context spans with labeled targets. Does not change scores. |
| `scaneval aggregate <run dir>... --output` | Weight every scheduled assignment of saved runs into corpus metrics with cluster-bootstrap intervals. |
| `scaneval compare <run dir>... --baseline --candidate --output` | Compare two systems assigned the same frozen work, with paired intervals. Decides no promotion. |
| `scaneval precision sample\|queue\|record\|estimate` | Sample delivered claims from saved runs, record human reviews, and estimate reviewed precision. Does not change scores. |
| `scaneval gate --policy --comparison --output` | Hold a comparison, and optionally precision estimates, to a gate policy and write a pass, fail, or inconclusive decision with every requirement explained. Promotes nothing. |

Run `scaneval <command> --help` for required arguments. `corpus validate --snapshot-id`, `blinding check`, `run`, `dataset fetch`, and `benchmark run` can reach the network; contacts depend on the configured sources and scanners. Exit code `2` means the command could not be carried out, `1` means it ran and reports a negative result, and `0` means it ran and reports nothing wrong. None certifies that a security label is correct.

## Scanners and visibility

The current adapters are `semgrep` with pinned local rules, `llm-harness` for an own-harness integration, and `deepsec` for the third-party scanner. `semgrep` (`--baseline-commit`) and `deepsec` (`process --diff`) also review a native PR request that names a base and a head commit in the scanner's workspace; [Current capabilities](docs/INITIAL_BUILD.md) says what each does with it. Scanner CLIs are installed separately. The optional `official-adapters` extra installs Semgrep; a reproducible comparison must also pin its version and rules.

The **ScanEval Observer SDK**, available in Python and TypeScript, records model calls, tool use, supplied context, and finding lifecycle events at instrumented boundaries. It is opt-in. Native collectors can import Claude Code and Codex records without claiming to see decisions the harness never exposed. Capture gaps remain explicit; traces cannot prove hidden reasoning or absence of memorization.

For the TypeScript SDK and harness driver:

```bash
npm ci --prefix sdk/typescript
npm run build --prefix sdk/typescript
```

The `llm-harness` adapter needs a local harness checkout and the built SDK. The `deepsec` adapter needs an installed scanner workspace; it runs the scanner in a separate private workspace.

Guides: [Observer SDK](docs/OBSERVER_SDK.md), [native CLI collectors](docs/COLLECTORS.md), [context-coverage diagnostics](docs/DIAGNOSTICS.md).

Implementation review: [Inspect AI visibility and observability comparison](docs/INSPECT_OBSERVABILITY_COMPARISON.md).

## Current limits

- Full-scan execution, native PR execution (a case pack declares a change set and states which targets and controls each PR review scores), case packs, source export, review, scoring, replay, and reports are implemented.
- Each run freezes its evaluation schedule (every assignment, pre-registered plan, and vulnerable/fixed pair) before it prepares an input. An input it cannot prepare is recorded with its skipped assignments, and the other inputs still run.
- The `metadata_blinded` profile applies a reviewed per-repository map to documentation and display metadata only. It is partial blinding, not anonymization: package names, source, and paths are unchanged.
- A saved SARIF 2.1.0 log imports offline into a bundle that review, score, and replay read; its execution report is recorded unverified ([SARIF import](docs/SARIF_IMPORT.md)). Other saved vendor formats have no importer.
- Enforced isolation exists for Semgrep only: a system whose 2.1 run configuration selects the `oci` execution backend runs each scanner process in a locked-down Docker container from a digest-pinned image, with its network policy enforced. `llm-harness` and `deepsec` are refused under it. Every other system runs as the operator, unenforced. See [the threat model](docs/THREAT_MODEL.md).
- Native PR review runs each scanner's own diff workflow over a neutral two-commit history of a declared change set: the harness's pr mode for `llm-harness`, `--baseline-commit` for `semgrep`, and `process --diff` for `deepsec`. An adapter without a PR mode is recorded as unsupported and stays in every denominator, and a full scan of the head never stands in for a PR review ([native PR review](docs/INITIAL_BUILD.md#native-pr-review)).
- Corpus aggregation and paired comparison read saved, frozen run directories ([aggregation](docs/AGGREGATION.md)). They compute no reviewed precision and decide no promotion.
- Reviewed precision comes only from people reviewing a seeded probability sample of delivered claims ([precision guide](docs/PRECISION.md)). It is not a repository false-positive rate.
- A gate decision holds a saved comparison to a policy you write and says whether its requirements held ([gate guide](docs/GATE.md)). It promotes nothing: the workflow that owns the harness decides.
- Fifty CVEs are selected in the [diverse corpus](corpus/diverse/README.md), including GitLab, Kubernetes, Airflow, Langflow, LangChain and Twenty. The [Astra-authored review skill](skills/cve-corpus-review/SKILL.md) supports machine review without a human gate; shared deployment context, claim-specific runtime validation and scanner preflight remain separate work. Java and Ruby are accepted by the corpus contract, but the current adapters still record them as unsupported. No representative benchmark or scanner comparison is claimed.
- External [dataset tracks](corpus/benchmarks/README.md) provide 469 PR cases and 223 additional OpenSSF CVE cases. Their publisher labels remain separate from the curated corpus. Dataset benchmark runs use the local execution backend; scoring measures reference coverage and named fixed controls, not true precision or an official upstream leaderboard score. Missing or uncertain semantic judgments remain explicit.

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
| `corpus/diverse/` | 50 selected CVEs, sourced severity distribution, pinned sources and machine review |
| `scripts/sanitize_native_trace.py` | Scrub native records for collector fixtures |
| `tests/` | Contract, scoring, runner, adapter, Observer, and collector tests |
| `docs/` | Public design and usage guides |

Generated runs belong under ignored `results/`; source caches belong under ignored `.repos/`. Do not commit scanner outputs, private findings, credentials, or content traces.

## License

[MIT](LICENSE). Source snapshots and external scanners retain their own licenses.
