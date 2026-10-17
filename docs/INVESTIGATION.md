# Investigating a saved run locally

`scaneval investigate` connects saved invocation results, targets, supplied matching decisions,
review records, artifact bindings, and trace events. It reads existing evidence and writes a
separate export. It does not run a scanner, call a model, rescore results, authenticate a
reviewer, or upload anything.

```sh
scaneval investigate results/my-run --output results/my-run-investigation
# Open results/my-run-investigation/index.html locally in your browser.
# The adjacent investigation.json contains the same exported evidence and joins.
```

The output must be a new directory outside saved runs and materialized trials. Existing
output directories are refused. The source run and every saved score remain untouched.
The HTML contains its own script and styles; no server, remote assets, or network access
is needed. Its content security policy blocks remote resources and connections.

## Following an outcome

1. Choose an invocation. Execution status, saved capture declarations, effective capture after
   trace validation, usage availability, and trace counts stay above every view.
2. In **Targets**, read the existing matching decisions and their reasons, alongside the saved
   outcome. A target with no recorded explanation says **unexplained**. This view does not infer
   why a scanner missed it.
3. In **Claims**, inspect the recorded allegation, matching and control judgments, original
   artifact binding, and related lifecycle events. `not_linked` means there is no usable explicit
   link; it is not a finding that activity never happened.
4. In **Events**, filter by exact type, producer, call, candidate, or claim. Related-event buttons
   navigate only recorded relationships. Capture remains visible when filters show zero events.
5. In **Bindings and review**, inspect current, stale, missing, malformed, and unavailable
   documents. Original byte hashes and canonical document hashes refer to the saved evidence
   before export redaction. A recorded reviewer identity or `human_approved` value is attribution
   in the saved record, not authenticated human approval.

The view displays saved `evaluation.json` outcomes and verifies their result, plan, and decision
hashes. It does not recompute them. Stale judgments remain readable with a stale label. Review
bindings include the plan and decisions, and an unavailable or stale result binding prevents a
current review claim. Execution run/input/system/repetition identities must agree with the manifest
row; result and execution input hashes must match the prepared manifest input, and the saved
input provenance must match its execution digest. Mismatches remain readable, are shown in
identity diagnostics, and prevent cross-document claims from appearing currently bound. Raw artifacts are checked by their declared SHA-256; their contents are
not copied into the export. Captured source, tool results, and prompts come from trace events.

## Filters and missingness

CLI filters narrow the exported events. Repeat a flag to OR its values; different flags are
ANDed. The HTML can further filter the exported events, but cannot recover events omitted by
CLI filters. Re-export without CLI filters to inspect those events.

```sh
scaneval investigate results/my-run --output results/read-investigation \
  --type tool.start --type tool.end --producer deepsec-adapter --call call-7
scaneval investigate results/my-run --output results/claim-investigation --claim finding-42
```

Other event flags are `--candidate` and `--type`. All comparisons are exact, including case.

Trace states are separate from execution success and capture completeness:

| State | Meaning |
| --- | --- |
| `unavailable` | No trace path was recorded, or the path could not safely be read. |
| `missing` | A recorded trace path no longer exists. |
| `empty` | The trace contains no nonblank records. |
| `malformed` | All nonblank records failed shared UTF-8/JSON/wire validation. |
| `partial` | Valid events survive alongside rejected records. |
| `valid` | Every nonblank record satisfies the wire contract; this does not imply complete capture. |
| `filtered_out` | Valid exported or source events exist, but the selected filters show none. The underlying trace state is retained. |

Physical lines, valid events, rejected records, exported events, and filter omissions are
separate counts. A saved event count differing from the validated count marks an effective
capture gap, including a valid truncated prefix or appended records. Validation gaps reconcile
effective capture using the same policy as bundle ingestion; original declarations remain visible. Missing usage remains unavailable. A source
span or verified delivery mapping does not prove model attention.

## Identity and time

Event relationships use `(saved run, invocation, event run namespace, producer)` plus the
explicit identifier. Identical call or candidate IDs in other producers or invocations never
merge. Parent IDs resolving to multiple physical events are **ambiguous**. Duplicate event IDs
remain separate rows, identified by an export-local `ref`. A claim links directly only to
explicit matching claim IDs in its saved run namespace; candidate lifecycle events extend that
link only inside the same producer scope. Unmapped native namespaces remain unlinked.

Events are sorted by their recorded observer timestamp, with stable input order for ties.
Known Claude/Codex imports label that timestamp **import emission time**. Native
`source_timestamp` and `source_timestamp_of` remain separate, verbatim labels; missing native
time is unavailable. This view never derives execution latency from import order, invents
per-event usage, or adds costs across potentially overlapping records.

## Private export policy

Content-mode traces retain useful private source paths, source text, prompts, and tool output.
The export is **not** the publication fixture sanitizer and is **not** anonymized. It replaces
credential-key values and recognizable credential assignments, bearer values, and private-key
blocks in the export copy. Every changed location is listed under `export_policy.redactions`.
This narrow policy is not a promise to recognize secrets in arbitrary prose. Treat both output
files as private evidence; supply them to any later LLM workflow only through an explicit action.

For metadata-mode traces, event `content` is excluded even if a malformed producer stored it.
Unknown trace modes also exclude content. Each such omission and each CLI filtering omission
is recorded. The original trace bytes, artifact hashes, raw artifacts, and judgments are untouched.
HTML renders evidence using text nodes and an inert JSON data block, not raw HTML. There are
no direct executable links to untrusted artifact paths.

Reads are limited to regular files within the selected run, using directory descriptors and
refusing symlink components, traversal, pipes, and devices. Individual files above 64 MiB are
reported unavailable rather than silently truncated. This is a local reader, not an operating
system sandbox; original artifact hashes remain the evidence for correspondence.

## Python API and JSON format

```python
from pathlib import Path
from scaneval.investigation import build_investigation, export_investigation

record = build_investigation(Path("results/my-run"), filters={"producer_id": ["deepsec-adapter"]})
export_investigation(Path("results/my-run"), Path("results/my-run-investigation"))
```

Both functions return the credential-redacted export copy. `build_investigation` writes nothing;
`export_investigation` writes `index.html` and `investigation.json` to a new private directory.
The JSON envelope declares `format: scaneval-investigation` and `format_version: 1.0`:

- `run`: validated manifest, original byte/canonical hashes, path and read state.
- `invocations`: saved row/status, capture and usage, document/read/binding states, claims,
  targets, raw-artifact binding checks, trace readability counts, and filtered event rows.
- Each event row: `ref`, full four-part `scope`, validated event, timestamp labels, and scoped
  links with all/visible references. References are local to that invocation.
- `filters` and `export_policy`: exact export filters, credential redactions, omissions, and limits.

This export is an input for later investigation, not a score, an approval, or a general live
query service. The shared trace reader is documented in [Observer SDK](OBSERVER_SDK.md);
coverage attribution is a separate [diagnostic](DIAGNOSTICS.md).
