# Dataset adapter council review — 2026-10-22

The council reviewed the dataset adapters and PR/CVE benchmark workflow at
`05acd923d0d953ad6995be290b34008f4a64720d`, then reproduced and reviewed fixes
through `af06bfc`. This was implementation review, not CVE-label adjudication or
a benchmark of real scanners.

Two independent Astra review roles examined adapter integrity and benchmark
scoring/persistence. Opus 5.5 independently reviewed a fixed packet of 20 committed
source, test, and documentation files, with tools disabled. Its retained CLI
receipt reports `claude-opus-5-5` plus a provider-side `claude-fable-5-1` advisor;
the advisor is not counted as another independent review. Reported list-price
usage was $3.9750746, within the approved $8 cap. This is the CLI's usage estimate,
not a verified invoice or total council cost.

At the user's request, GPT-5.6-Sol implemented the remaining scoring changes;
Astra reviewed that diff and independently reproduced the corrected behavior.
The council used evidence and executable checks to resolve disagreements rather
than treating model agreement as proof.

## Findings and disposition

| Finding | Resolution | Commit |
| --- | --- | --- |
| Replacing source and its neighboring provenance could reuse old judgments | Bind execution/provenance digests, recompute snapshot or PR input identity, and carry verified bindings in judge packets | `97cdbef` |
| Setup interruption or abrupt process exit could leave finished scans unscoreable | Write an initial record before setup and atomically checkpoint prepared inputs and completed invocations | `e69bfb4` |
| Case-only task/system/invocation IDs collide on macOS | Reject case-folded collisions before running | `2921b68` |
| A trailing newline bypassed ID and commit validation | Require the actual end of the string in the common schema | `2921b68` |
| Failed-result claims required judgments despite being ineligible for credit | Preserve delivered counts and raw claims; match only success/partial claims, with explicit eligible/excluded counts | `af06bfc` |
| Unobserved runtime appeared as zero | Report an unknown total as null; retain measured zero | `af06bfc` |
| System-array copying could imply unsupported isolation settings | Name rejected fields and document the supported subset | `af06bfc` |

The final change also checks original provenance commits against frozen dataset
pins and clarifies that omission of the explicit label field does not make the
judge protocol blinded. Task IDs, source context, and publisher ordering can
still provide cues.

Opus's conditional suspicion that AACR base/head were reversed was rejected:
the [pinned publisher converter](https://github.com/alibaba/aacr-bench/blob/ee9d7fef70ef31acea2ff7ae316ce0a9575fe4df/evaluation/converters/aacr_bench.py#L170)
explicitly maps `source_commit` to base and `target_commit` to head. Its retained
blob and SHA-256 matched the pinned download receipt. All 450 actual data-file
reads across the four imported releases were members of their locks, and all
shipped lock entries included Git blob IDs. Built-in plugin precedence also
matched the documented behavior; these were not confirmed defects.

## Validation and compatibility

- 77 adapter/benchmark tests passed: 33 adapter tests and 44 benchmark tests.
- 304 additional contract, PR, adapter-mode, materialization, and CLI regression
  tests passed during the review.
- Independent reproductions covered snapshot/PR source replacement, receipt
  reassignment, interruption during setup and scanning, failed checkpoint writes,
  and a real child process exiting abruptly before Python cleanup ran.
- All four full imports retained identical canonical hashes and inventory
  summaries: AACR 200 tasks, ReviewBench 219, Martian 50, OpenSSF 446.
- Astra's final narrow review found no further concrete regression in Sol's fix.

Scoring now identifies itself as `scaneval-reference-coverage-2`. Its claim-rate
denominator and required judgment set differ from version 1. This prerelease
refuses old plans, packets, and judgments: create a new plan and run. No real
benchmark results were produced or migrated during this review.

## Evidence and limits

The [evidence manifest](DATASET_COUNCIL_2026-10-22.json) records artifact hashes,
the reviewed/fixed commits, model provenance, and validation counts. Full prompts,
responses, reviewer notes, and local repros remain under the ignored
`results/council-review-20261022/` directory in the working checkout.

The local runner remains unenforced; hashes are consistency checks, not signatures.
Reference matching is not independent vulnerability validation or true precision.
Publisher labels were not re-adjudicated, and no real scanner comparison was run.
Optional follow-ups include stricter JSONL example parsing, parsing verified source
bytes without a second read, clearer malformed-pin diagnostics, mirror-fallback
test coverage, and per-repetition uncertainty reporting. These were not required
to close the reproduced findings above.
