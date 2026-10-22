# Installable dataset adapter example

Install into the same environment as ScanEval:

```sh
python -m pip install --no-deps -e examples/dataset_plugin
scaneval dataset list
```

The `example-jsonl` adapter reads a source directory with:

- `dataset.json`: the common format's `schema_version`, `dataset_id`, `mode`,
  `source`, and optional `metadata`, without a `tasks` field.
- `tasks.jsonl`: one common-format task object on each nonblank line.

```sh
scaneval dataset import --adapter example-jsonl --source my-data --output results/custom.json
scaneval dataset validate results/custom.json
```

Use `results/custom.json` with the same `benchmark plan`, `benchmark run`,
`benchmark judge-packet`, and `benchmark score` commands as any built-in dataset.
See [the dataset guide](../../docs/DATASET_ADAPTERS.md) for the task and annotation
contract. Replace this translator and entry-point name for your own source format.
No ScanEval registry changes are required.
