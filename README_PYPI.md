# ScanEval

ScanEval evaluates security scanners on versioned cases and records how instrumented
harnesses reach their findings. It includes a CLI, versioned data contracts, offline
replay, local reports, and the opt-in Python Observer SDK.

**Alpha release: `2.0.0a1`.** No benchmark results or scanner comparisons are published.
The selected corpus contains 50 CVEs, but fixed controls remain unvalidated and scanner
miss rates remain unmeasured. Live scanner integrations need separate installations and
configuration. The default SV-Agent harness pin cannot yet produce a completed
source-scan score. See the
[current capabilities and limits](https://github.com/Har1sh-k/scaneval/blob/main/README.md#current-limits).

## Install and try the offline demo

Requires Python 3.11 or newer. Source materialization also requires Git. From a virtual
environment on macOS or Linux:

```bash
python -m pip install "scaneval==2.0.0a1"
scaneval demo demo-run
scaneval replay demo-run --output demo-replay.json
```

Open `demo-run/report.html` locally. The demo uses fabricated evaluator fixtures and
makes no scanner or model calls. Output paths must be new. Run `scaneval --help` for
commands; the
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
describes sinks, recording modes, and capture states. A
[TypeScript SDK](https://github.com/Har1sh-k/scaneval/tree/main/sdk/typescript)
shares the trace contract.

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
