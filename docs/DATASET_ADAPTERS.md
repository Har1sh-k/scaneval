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
