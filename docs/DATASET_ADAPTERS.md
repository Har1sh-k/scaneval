# Dataset adapters

Dataset adapters translate a source dataset into ScanEval's common dataset
contract. Scanner adapters execute tools. Neither interface chooses the other's
labels or settings.

The built-in dataset adapters are `aacr-bench`, `reviewbench`, `martian`, and
`openssf`. The first three use `pr-review` mode; OpenSSF uses `cve-detection` mode
with separate vulnerable and fixed tasks. `native` reads the common format
directly. Every adapter, including installed plugins, passes the same validation.

## Fetch and import

```sh
scaneval dataset list
scaneval dataset fetch aacr-bench --output .repos/datasets/aacr-bench
scaneval dataset import --adapter aacr-bench \
  --source .repos/datasets/aacr-bench --output results/aacr-bench.json
scaneval dataset inspect results/aacr-bench.json
scaneval dataset validate results/aacr-bench.json
```

Use any built-in name in those commands. Create the output parent directory first.
Fetch downloads pinned annotation files, documentation, and licenses; it does not
download all target repositories or execute upstream code. It verifies both file
SHA-256 hashes and upstream Git blob IDs. A failed fetch removes its own incomplete
directory. Existing output directories and files are never overwritten.

Import is offline and verifies the complete source lock before translation. Use
`native` or a custom adapter for a modified dataset instead of editing locked
source files. `corpus/benchmarks/inventory.json` records counts from imports of the
actual pinned releases. No scanner results are included in that inventory.

## Bring a dataset without writing Python

Supply JSON matching [`dataset.schema.json`](../src/scaneval/schemas/dataset.schema.json),
then run:

```sh
scaneval dataset import --adapter native --source my-cases.json --output results/my-dataset.json
```

The top-level fields are `schema_version: "1.0"`, `dataset_id`, `mode`, `source`
(`name`, `revision`, `license`), and `tasks`. Each task names:

- A unique `task_id`, a logical `case_id`, an HTTPS `repository_url`, a full
  40-character `commit`, and nonempty `languages`.
- For PR review: `variant: "pr"` and a different full `base_commit`. The `commit`
  is the head. For CVE detection: `variant: "vulnerable"` or `"fixed"`, with no
  `base_commit`. Give paired vulnerable/fixed tasks the same `case_id`.
- `annotations`, each with a task-local `annotation_id`, `text`, `label`,
  `locations`, `category`, and `severity`.

Annotation labels have distinct meanings: `positive` is a publisher-accepted
issue, `negative` is a rejected review allegation, and `fixed-control` is the
specific issue expected absent from a fixed snapshot. A rejected comment never
turns the PR into a safe control. A fixed control never declares an entire
repository free of vulnerabilities.

Locations have repository-relative POSIX `path`, optional `side` (`base`, `head`,
or `snapshot`), and optional positive `start_line`/`end_line`. Use an empty array
when no reliable location is known. Severity is `critical`, `high`, `medium`,
`low`, `informational`, or `unspecified`. Do not invent severity to fill a chart.
Free-form `metadata` on datasets, tasks, and annotations retains additional
evidence. The importer checks structure and identity; it does not establish that
an allegation is true or execute a vulnerability.

## Add a Python adapter

Implement an offline, deterministic translator:

```python
from pathlib import Path
from scaneval.datasets import DatasetAdapter

class CompanyDataset(DatasetAdapter):
    name = "company"

    def load(self, source: Path) -> dict:
        # Read your source files and return the common dataset JSON structure.
        return translate_company_files(source)
```

Register it in your package's `pyproject.toml`:

```toml
[project.entry-points."scaneval.datasets"]
company = "company_eval.dataset:CompanyDataset"
```

Install that package into ScanEval's environment. It then appears in
`scaneval dataset list` and works with `--adapter company`, without editing the
registry or evaluator. The plugin is trusted installed Python code; a JSON
dataset itself cannot cause a plugin to be imported. Duplicate plugin names are
refused and built-in names cannot be replaced by a plugin.

An [installable JSONL example](../examples/dataset_plugin/README.md) includes the
complete package and entry point. It feeds the same benchmark commands after
import, so a third-party adapter does not need its own runner or scorer.

## Source-specific details

AACR-Bench preserves correct and incorrect comments, their producer information,
and diff sides. One invalid upstream span remains in annotation metadata, with a
warning and no invented normalized line numbers. Its GitHub pin has one different
label from the separately published Hugging Face version.

ReviewBench retains producer, scope, difficulty, correctness, category, severity,
and justifications, and provides the publisher's mirror URL for source fetching.
Pre-existing findings remain explicitly marked in their original metadata.

Martian's golden files omit source commits and file locations. Frozen PR API
responses supply base/head commits, while unknown locations stay empty. Its five
project collections currently resolve to seven source repositories, including
benchmark forks and the Cal.com redirect. The API pins are an integration choice,
not a claim to reproduce a historical vendor run.

OpenSSF has 223 CVE cases, each with two tasks. Multiple upstream weakness
locations belong to the same CVE target. Two abbreviated fixed commits are
expanded using recorded API evidence. One upstream `/index.js` anchor is
normalized to repository-relative `index.js` with a warning. The five upstream
`implicitExtension` flags remain in original metadata. Fixed controls carry no
copied pre-patch line numbers. Neither OpenSSF nor AACR supplies severity in these
source files, so it remains unspecified.

Each source is scored separately; matching and denominator choices must be
reported with results. Imported annotations are not additional machine-reviewed
labels in the existing 50-CVE corpus, and imported vendor labels do not become
ScanEval human approvals.

## Execute and evaluate a dataset

The common dataset format feeds the scanner runner through `benchmark` commands.
The execution uses ScanEval's existing source export, neutral Git history, adapter
capability checks, private workspaces, raw output capture, timeouts, and usage
records. A PR task invokes the tool's PR workflow. A CVE task invokes a full
snapshot scan. Unsupported languages and modes remain scheduled observations.

Create `systems.json` as a JSON array of scanner specifications. Each element uses
the same `system_id`, `adapter`, `config`, and optional `model_id`/`model_revision`
fields as the [existing runner configuration](INITIAL_BUILD.md#run-configuration).
When adapting an existing systems array, retain only those fields. The case-pack
runner's `execution` and `network_policy` keys are intentionally unsupported here;
the benchmark validator rejects them rather than silently discarding isolation
choices. Installing a dataset does not install a scanner or select a model. The
existing scanner adapters are `semgrep`, `llm-harness`, and `deepsec`.

```sh
scaneval benchmark plan --dataset results/aacr-bench.json \
  --systems systems.json --run-id aacr-comparison-v1 --repetitions 3 \
  --output results/aacr-plan.json

scaneval benchmark run --plan results/aacr-plan.json \
  --dataset results/aacr-bench.json --cache .repos/benchmark-sources \
  --output results/aacr-run

scaneval benchmark judge-packet results/aacr-run --output results/aacr-judge-packet.json
```

Use repeated `--task TASK_ID` arguments when planning a selected subset. Selection
and repetitions are frozen before any scanner runs. Use a separate plan and run
ID for a smoke test. Keep tool/model versions, rules, and budgets fixed for a
comparison. Dataset identity includes all annotations and metadata; changing it
invalidates an existing plan.

The dataset runner currently uses the local backend, recorded as unenforced in
the run and invocation records. Filesystem and network isolation are not implied
by putting labels outside scanner workspaces. The existing case-pack runner's
OCI option remains a separate workflow.

`benchmark run` writes `plan.json`, `dataset.json`, `schedule.json`, prepared source
trees, invocation bundles, and `benchmark-run.json`. It never overwrites a run.
Failures during source or scanner preparation are retained. Runtime failures,
partial outputs, unsupported cases, and timeouts remain in denominators. The
run record exists before scanner setup and is atomically checkpointed after each
prepared input and completed invocation. An interrupted run retains completed
assignments; assignments without a completed checkpoint remain missing, including
an invocation interrupted while running. Interrupted runs can be inspected and
scored but are not resumed by this command. The exit status is 1 if any recorded
invocation is not successful.

## Machine judgments and deterministic scoring

The judge packet contains each claim eligible for matching and the task's reference
annotations. The explicit correctness `label` field is omitted, but task and
annotation IDs, publisher ordering, annotation text, and source context may reveal
variant or label cues. This is neither tool-blinded nor label-blinded evaluation.
Repository, claim, and annotation content is untrusted evidence for the matcher,
not instructions. The packet also names
the saved source trees so a judge can inspect context. Invocation IDs can expose
tool names; this is not a blinded judge protocol. Before emitting the packet,
ScanEval verifies the execution and provenance digests, rehashes the saved source,
and compares its input identity with the scanner result. PR inputs include both
trees and a recomputed diff. The packet carries these verified identities, so
replacing source and its neighboring provenance cannot reuse old judgments. These
are consistency checks over retained artifacts, not signed or tamper-proof records.

Give the packet to a Codex/LLM judge or another semantic matcher. No human approval
is required. It must match the same concrete issue, not merely a shared path,
line, keyword, or CWE. A judgment response has this shape (replace the illustrative
IDs and hash with the actual packet's values):

```json
{
  "schema_version": "1.0",
  "packet_sha256": "sha256:<canonical packet hash printed by judge-packet>",
  "judge": {"kind": "llm", "name": "my-judge", "model": "exact-model-revision"},
  "decisions": [
    {
      "invocation_id": "task__system__r1",
      "claim_id": "claim-1",
      "annotation_ids": ["a00001"],
      "status": "decided",
      "reason": "Both describe the same unchecked authorization path."
    }
  ]
}
```

An unmatched claim uses `annotation_ids: []`. An unresolved judgment uses
`status: "uncertain"` and an empty annotation list. Preserve the judge's actual
prompt, response, and execution receipt alongside this response for publication;
the scorer verifies bindings but does not authenticate a claimed model identity.
It makes no model call itself. Test fixtures use `judge.kind: "test"` and are not
benchmark evidence.

```sh
scaneval benchmark score results/aacr-run \
  --judgments results/aacr-judgments.json --output results/aacr-score.json
```

Re-running score with the same saved inputs produces the same document, offline.
The report names its protocol, source and plan hashes, judge, judgment hash, status
counts, severity breakdown, runtime, available token counts, and known cost.
Unknown cost and runtime totals are `null`, with counts of invocations that
reported each value. A runtime total with some missing invocations is the sum of
known values only.

Each system row also names the `adapter_version` its saved receipts record (`null`
when none ran; receipts naming two versions of one system are refused) and its
`processing`, `curated` or `full`, decided as in [aggregation](AGGREGATION.md): a
DeepSec configuration naming `process_manifest_by_tree` is `curated` unless its
receipts record an adapter before 1.2.0, which ignored the key. A curated system is
scored like any other, and `limits` gains a line saying its figures describe the
paths chosen before the run and are not a detection rate.

The `scaneval-reference-coverage-2` protocol uses these rules:

- Reference coverage is distinct positive annotations covered divided by all
  positive annotations assigned to that system across the scheduled repetitions.
  Errors, timeouts, unsupported tasks, and missing results do not shrink that
  denominator. Each repetition has its own annotation coverage.
- `generated_claims` counts every normalized claim retained in result artifacts.
  Only claims from `success` and `partial` results are `scorable_claims`; claims
  from all other statuses are `excluded_claims`. Excluded claims remain in the
  saved result for audit but are omitted from the packet's matchable `claims`, do
  not require judgments, and do not enter pending/uncertain counts or the match-rate
  denominator. Packet invocation counts make this exclusion explicit.
- One scorable claim may cover several annotations. A repeated claim contributes to
  `novel_reference_match_rate` only when it covers a previously uncovered positive
  annotation in that invocation. Its denominator is `scorable_claims`, counted in
  delivered order. The protocol identifier changed from version 1 because this
  denominator and the required judgment set changed. This prerelease refuses
  protocol-v1 plans, packets, and judgments; create a new v2 plan and run rather
  than silently migrating or reusing old results.
- A match to a rejected annotation is reported separately. It never grants
  positive coverage or quiet-control credit.
- Fixed controls report `alerted`, `quiet`, and `unresolved`. Silence earns quiet
  credit only for a successful completed scan with resolved bundles, no known
  omitted paths or empty examination, and no pending claim judgments. A partial
  or failed scan cannot earn quiet credit.
- Missing or uncertain judgments leave the final coverage rate `null`; confirmed
  coverage is still reported as a lower bound. Confirmed execution failures can
  produce a completed zero-coverage observation.

Reference coverage is not a count of unique real vulnerabilities. The match rate
is not precision: unmatched findings may identify valid issues absent from the
dataset. This protocol also differs from each publisher's own matching, dedup,
scope, and missing-result rules. Report it as a ScanEval evaluation of the pinned
dataset, not as that publisher's official leaderboard score. Do not combine the
four datasets into a single unlabeled score.
