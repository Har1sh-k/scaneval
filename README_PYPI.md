# ScanEval

ScanEval evaluates structured security-scanner results against a versioned plan and
supplied review decisions. Import the Python package and call
`scaneval.evaluate(plan, result, decisions)` to produce an evaluation report offline.
The same distribution includes a CLI, versioned data contracts, replay, local reports,
and optional tracing through `scaneval.observer`.

**Alpha version: `2.0.0a2`.** No benchmark results or scanner comparisons are published.
The selected corpus contains 50 CVEs, but fixed controls remain unvalidated and scanner
miss rates remain unmeasured. Live scanner integrations need separate installations and
configuration. The default SV-Agent harness pin cannot yet produce a completed
source-scan score. See the
[current capabilities and limits](https://github.com/Har1sh-k/scaneval/blob/main/README.md#current-limits).

## Install and evaluate

Requires Python 3.11 or newer. Source materialization also requires Git. From a virtual
environment on macOS or Linux:

```bash
python -m pip install "scaneval==2.0.0a2"
scaneval demo demo-run
```

The demo writes a complete set of saved records to `demo-run`: an evaluation plan, a
normalized scan result, and review decisions. They are fabricated evaluator fixtures; no
scanner or model is called. Evaluate them:

```python
import json
from pathlib import Path
import scaneval

bundle = Path("demo-run")
plan = json.loads((bundle / "evaluator" / "plan.json").read_text(encoding="utf-8"))
result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
decisions = json.loads((bundle / "evaluator" / "decisions.json").read_text(encoding="utf-8"))

report = scaneval.evaluate(plan, result, decisions)
print(json.dumps(report, indent=2))
```

The report matches the demo's own `demo-run/evaluation.json`. Load your own saved plan,
result, and decisions the same way.

Scoring requires structured saved records and supplied finding-review decisions bound to
those records. The plan assigns targets and controls; the decisions say which findings
establish their alleged issues. Unreviewed findings remain unresolved. The evaluation API
validates these inputs and computes scores; producing scanner findings and adjudicating
natural-language allegations are separate steps.

## Replay the demo

```bash
scaneval replay demo-run --output demo-replay.json
```

Replay recomputes the saved bundle offline. Open `demo-run/report.html` locally. Output
paths must be new. Run `scaneval --help` for commands; the
[execution guide](https://github.com/Har1sh-k/scaneval/blob/main/docs/INITIAL_BUILD.md)
explains scanner configuration, review, and saved evidence.

## Instrument a Python harness

The public Python SDK is available from `scaneval.observer`. Emit events at the model,
tool, context, and finding boundaries your harness exposes:

```python
from scaneval.observer import Observer

events = []
observer = Observer(
    mode="metadata",
    sink=events.append,
    run_id="example-run",
    producer_id="my-harness",
)
observer.emit(
    type="model.request",
    capture_status="complete",
    call_id="call-1",
    metadata={"model": "example-model"},
)
observer.flush()
observer.close()
```

This example records one event in memory; it calls no model. Recording defaults to
`off` unless the caller chooses a mode. Capture gaps remain explicit, and traces cannot
prove hidden reasoning. The
[Observer SDK guide](https://github.com/Har1sh-k/scaneval/blob/main/docs/OBSERVER_SDK.md)
describes sinks, recording modes, and capture states. This Observer is part of `scaneval`;
no separate Python Observer distribution is needed. A
[TypeScript SDK](https://github.com/Har1sh-k/scaneval/tree/main/sdk/typescript)
shares the trace contract and remains available as source. This release publishes only
the Python `scaneval` distribution.

## Cases, datasets, and execution limits

Start with the
[selected CVE corpus](https://github.com/Har1sh-k/scaneval/blob/main/corpus/diverse/README.md),
[bring your own corpus](https://github.com/Har1sh-k/scaneval/blob/main/docs/BRING_YOUR_OWN_CORPUS.md),
or [dataset adapters](https://github.com/Har1sh-k/scaneval/blob/main/docs/DATASET_ADAPTERS.md).
Scoring uses supplied review decisions; unreviewed findings remain unresolved.

The local execution backend runs scanners as the operator and enforces no isolation.
The OCI backend supports specific adapters and configurations; read the
[threat model](https://github.com/Har1sh-k/scaneval/blob/main/docs/THREAT_MODEL.md)
before live runs. Keep scanner outputs, private findings, credentials, and content traces
local.

[Source and issues](https://github.com/Har1sh-k/scaneval) are on GitHub. ScanEval is
[MIT licensed](https://github.com/Har1sh-k/scaneval/blob/main/LICENSE); external scanners
and source snapshots retain their own licenses.
