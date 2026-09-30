# SARIF import (profile `sarif-import-1`)

`scaneval import sarif` reads one run of a saved [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
log that some other tool wrote, somewhere else, and writes a new bundle that `review`, `score`,
`replay`, and `report` read exactly as they read a bundle `scaneval run` wrote. It runs no scanner
and makes no network call. The log is untrusted input: nothing it names is fetched or opened, not
its `$schema`, not a rule's `helpUri`, and not a path in a location, which is a string to map into
the scanned tree or to refuse. Whatever the log says about how its tool ran is recorded as the
log's own report and never verified.

The code is [`src/scaneval/sarif.py`](../src/scaneval/sarif.py); the tests are
[`tests/test_v2_sarif.py`](../tests/test_v2_sarif.py), over fabricated logs in the shapes Semgrep
OSS 1.177 and CodeQL 2.26 write.

## Command

```sh
scaneval import sarif results/codeql.sarif \
  --pack corpus/pilot/pack.json --snapshot-id <snapshot> --tree-hash sha256:<64 hex> \
  --system-id codeql-2.26 --output results/codeql-import
```

The result binds to the snapshot, tree hash, and system the operator declares, never to anything
the log says about itself; the plan is `cases.build_plan` for that snapshot and hash, which refuses
a snapshot whose recorded tree hash is a different one. When the pack records no tree hash for the
snapshot, the binding is the operator's declaration alone, and `import.json` says so.

| Option | Meaning |
|---|---|
| `--run-index N` | Which run to import; required when the log holds more than one. |
| `--run-id ID` | Default `import-<first 12 hex of the log's SHA-256>-r<N>`, so one log always imports under one id. |
| `--system-config FILE` | A JSON object describing the system. Only its canonical SHA-256 is recorded. |
| `--source-dir DIR` | The exported tree. It must hash to `--tree-hash`; every mapped path and line is then checked against it. |
| `--uri-base NAME=URI` | Where a `uriBaseId` points: a directory inside the scanned tree ending in `/` (`.` for its root), or a `file` URI under `--source-root-uri`. Repeatable; a name given twice is refused. |
| `--source-root-uri URI` | The absolute `file` URI of the scanned tree's root on the machine that wrote the log. |
| `--normalization FILE` | Recorded bundle-review decisions, described below. |
| `--include-suppressed` | Import suppressed results as claims. Their suppression is recorded either way. |
| `--max-bytes N` | Refuse a larger log. Default 64 MiB. A message is bounded on its own (65536 characters, written or formatted) and each taxonomy and rule is read once, so a small log cannot become a large allegation or a long run; results that share one long string still each carry a copy of it, up to that bound. |

`--system-config` and `--normalization` files are read as strictly as the log, up to 1 MiB each.
Exit codes: `2` when the log is refused whole or an option cannot be used, and then nothing is
written; `1` when the bundle was written but its status is `error`, so it holds no usable scan;
`0` otherwise, with a `partial` status's reason printed on stderr.

## The bundle

```text
<output>/
  raw/<log name>.sarif           the log's bytes as supplied
  result.json                    scan-result 2.1
  import.json                    import-record 2.1: what happened to every result
  evaluator/plan.json            the plan for the declared snapshot and tree hash
  evaluator/decisions.json       machine draft: every decision unresolved
  evaluator/review-record.json   draft review record
  evaluation.json                the score of the draft
  report.html
```

A SARIF log carries no timing, cost, or model identity, so none is invented: `usage` is
`{"wall_seconds": null}`, which is why `result.json` is scan-result 2.1. Claims are `unranked`:
SARIF array order has no meaning and `rank` and `level` are scores, not a delivered review order,
so no review-budget recall is read from an import. The log's SHA-256 is recorded in `result.json`
(`raw_artifacts`, id `sarif`, which every claim cites) and in `import.json`. There is no
`request.json` or `execution.json`, because nothing ran; `import.json` records the import instead.

Everything is built and validated before the directory exists, the output must not exist, every
file is created exclusively, and a write that fails part way removes what the import created,
including any parent directory it had to make (one that was already there stays, and so does a
directory that holds anything the import did not write). An output path inside a trial directory,
or inside `--source-dir`, is refused.

## Refused whole

The log is refused, and nothing is written, when it cannot be read as a regular file; is larger
than `--max-bytes`; is not UTF-8 (a leading byte order mark is ignored and noted); is not JSON;
repeats an object key; holds `NaN` or an infinity (spelled as a constant or as a number too large
for a float) or a string with a lone surrogate; nests past the parser's recursion limit; declares a
`version` other than `2.1.0`; has `runs` missing, `null`, or empty; holds more than one run without
`--run-index`, or a run index out of range; or carries `externalPropertyFileReferences` on any run
or on the log object, whatever its value, because an offline import would present the inline part
of such a run as the whole of it. A selected run without `tool.driver.name`, or with a container
property of the wrong JSON type, is refused too.

## Every result: a claim, an exclusion, or a loss

`import.json` accounts for every result of the run exactly once, and its validator checks that.

- **Claim.** A result of kind `fail` (the default), `review`, or `open` whose rule, message, and
  primary location resolve. One result is at most one claim, id `r<run>-<index>`.
- **Exclusion**, counted and listed with its reason: kind `pass`, `notApplicable`, or
  `informational`; `baselineState` `absent` (not detected in this run); and a suppressed result
  unless `--include-suppressed` is given. A result is suppressed when `suppressions` is non-empty
  and no entry's `status` is `underReview` or `rejected`. SARIF states no rule for an entry without
  a status; it counts as suppressed here, as the SARIF SDK reads it, and it is how Semgrep writes a
  `nosemgrep` match.
- **Loss**, listed with its reason: a rule reference that conflicts with itself or names a
  descriptor ambiguously, a message that does not resolve (a placeholder index of more than nine
  digits, or a message of more than 65536 characters, included), a primary location that is not a file in the scanned tree, malformed
  coordinates, a value outside SARIF's enumerations, or anything else that raised a `ValueError`
  while the result was read, so that no one result can end the import. Any loss sets
  `bundles_resolved` false and turns an otherwise clean run into `partial` with error code
  `import_loss`, so a scan whose finding could not be read earns neither completeness nor quiet
  credit.

| Claim field | Where it comes from |
|---|---|
| `allegation` | The full resolved message: its `text`, else the rule's `messageStrings[id]`, else the component's `globalMessageStrings[id]`, formatted with `arguments` (`{n}`, and `{{`/`}}` for literal braces). A `text` is formatted only when it carries `arguments`, because producers that use none write braces unescaped. Markdown is never read. A message of more than 65536 characters, as written or once formatted, is a loss. |
| `native_rule_id` | The resolved descriptor's `id`, else the result's `ruleId` or `rule.id`. |
| `native_severity` | The effective level (`result.level`, else the rule's `defaultConfiguration.level`, else `warning`), followed by `; security-severity N` when the rule has that GitHub property. For `review` and `open`, the kind. |
| `native_cwe`, `kind` | CWE ids from the rule's `superset`/`equal` relationships to the CWE taxonomy, the result's `taxa`, then rule and result tags (`CWE-89: ...`, `external/cwe/cwe-089`), leaving out an id of more than nine digits, which is not a CWE; `native_cwe` lists them in that order, and `kind` is the versioned kind mapping's kind for the lowest-numbered of them it knows, whatever order they came in, else `unmapped`. |
| `native_id` | `result.guid`, when present. |
| `primary_location` | `locations[0]`. |
| `related_locations` | `locations[1:]`, then `relatedLocations`. |
| `evidence_text` | `codeFlows`, one line per step in execution order: `flow i, thread j, step k: path:line message`. |

Rules are found as SARIF 3.52.3 says: the component `rule.toolComponent` names (an index into
`tool.extensions`, or a `guid`), else the driver; within it, by `rule.index`/`ruleIndex`, else by
`guid`. Semgrep names a rule by `ruleId` alone, so a lone id is matched whole, then less one
trailing hierarchical component. `ruleId` against `rule.id`, and `ruleIndex` against `rule.index`,
must agree. A result whose rule has no descriptor keeps its own id, and a note says its level and
CWE ids came from the result alone.

`fingerprints` and `partialFingerprints` are recorded per claim in `import.json` as provenance,
with Semgrep's login-gated `requires login` recorded as `null`. They are never a claim's identity:
exact-duplicate identity is the canonical claim, as for every other claim.

## Locations

A location's `artifactLocation` maps to a path in the scanned tree in this order:

1. `index` names `run.artifacts[index]`, which must exist and not be nested in another artifact;
   when `uri` is present too, both must name the same file.
2. `uriBaseId` resolves through `--uri-base` first, then `run.originalUriBaseIds` (chains are
   followed; a loop, an entry URI without a trailing `/`, and an entry that hides its `uri` do not
   resolve), then `%SRCROOT%` in any case, or no base at all, as the scanned tree's root. Any other
   base is a loss.
3. An absolute `file` URI, written in the location or reached through a base, maps only under
   `--source-root-uri`; any other scheme is a loss.
4. The path is percent-decoded one segment at a time as UTF-8. A `..` segment, an absolute path, a
   leading `//`, a drive letter, a query or fragment, a backslash, a NUL, and an encoded slash or
   backslash inside a segment are refused rather than resolved.
5. With `--source-dir`, the path must be a regular file in the exported tree's listing (a symbolic
   link is not) and the region's last line must be within the file. Without it the mapping is
   recorded as unverified (`source_binding.source_dir_verified` false).

Lines come from `startLine` and `endLine` only. `endLine` defaults to `startLine`, and `endColumn`
1 on a later line ends the region with the line before it. A location with no region is the whole
file, and one whose region gives only `charOffset` or `byteOffset` stays file-only with a note:
lines are never computed from offsets. Malformed coordinates are a loss.

A primary location that does not map is a loss. A related location or a flow step that does not
map, a message link `[text](n)` that does not name exactly one location of the result (one of more
than nine digits names none), and flow steps past the rendering bound (256 steps or 64 KiB) are
**evidence losses**, recorded against the claim, which stays.

## Bundle review and the normalization file

A result is flagged for bundle review when `locations` holds more than one entry
(`multiple_locations`) or its code flows start in different places, or at a place that cannot be
mapped (`divergent_code_flows`). Either can mean one allegation or several bundled into one result,
and the importer never splits or guesses. A flagged result keeps `bundles_resolved` false unless
the normalization file records a decision for it that a person made:

```json
{"artifact_sha256": "sha256:<the log's SHA-256>",
 "decisions": [{"pointer": "/runs/0/results/2", "decision": "atomic",
                "reviewer": "<the reviewer's own name>", "note": "<what was read>",
                "at": "<optional time>"}]}
```

The file must name this log by digest, and each decision must name a result this import flagged,
at most once. The only decision that can be recorded is `atomic`: the result is one allegation and
stays one claim. The reviewer is taken as written and never supplied by the tool. The decisions and
the file's canonical SHA-256 are embedded in `import.json`. Import loss or an absent result list
keeps the bundles unresolved whatever was decided.

## Execution evidence and status

| What the log reports | `execution.evidence` | Status and error code |
|---|---|---|
| `run.results` `null` or absent | from the invocations, as below | `error`, `results_absent`, no claims |
| An invocation with `executionSuccessful: false`, an `error`-level execution or configuration notification, or an `exitSignalName` or a `processStartFailureMessage`, each even beside `executionSuccessful: true` | `reported_failed` | `partial` when a claim was imported, else `error`; `execution_failed` |
| No invocation, or one whose `executionSuccessful`, `exitSignalName`, `processStartFailureMessage`, or a notification's level cannot be read | `unreported` | `partial`, `execution_unreported` |
| Otherwise | `reported_success` | `success` |

A notification's level is its own `level`. Without one it is what the invocation's
`notificationConfigurationOverrides` give the notification's descriptor (SARIF 3.58.6), else the
descriptor's `defaultConfiguration.level`, else `warning`, which is also the level of a notification
that names no descriptor. A descriptor is found by `index`, `guid`, or `id` in the component its
reference names, and an override applies when it names the same descriptor, whichever of the three
each one uses. What cannot be read is never taken for `warning`: a level that is not `none`, `note`,
`warning`, or `error` (in the notification, an override, or a default), a descriptor the log does not
hold or names ambiguously, and overrides that cannot be matched to a descriptor or that disagree
make the evidence `unreported`. So does an `exitSignalName` or `processStartFailureMessage` that is
not a string; an empty one says nothing. Import loss makes a run that would otherwise be `success`
`partial` with `import_loss`. Every reason that applies is named in the error message, and the error
code is the first of them in the table's order. `execution.verified` is always false. Because only a
`success` scan over resolved bundles can establish a quiet control, a log that does not report its
execution earns no quiet credit, even with no results at all.

## Producer notes

**Semgrep** writes `ruleId` only, `%SRCROOT%` without `originalUriBaseIds`, flow steps with no
`uriBaseId`, `requires login` fingerprints when not logged in, and `executionSuccessful: true`
even beside an error notification for a scan that exited 2. Its rule ids carry the rule file's
directory, dotted, in both its JSON and its SARIF. The live `semgrep` adapter strips the ruleset
checkout root it pinned; an import has no checkout to strip and keeps the id as written, so the
same finding's `native_rule_id` and exact-duplicate fingerprint differ between the two paths while
everything else, and the score under the same decisions, agrees
(`test_one_semgrep_finding_scores_alike_through_the_adapter_json_path_and_a_sarif_import`, and
`test_real_semgrep_json_and_sarif_from_one_scan_score_one_finding_alike` against the real binary).
That includes `kind`, which both paths take from the lowest-numbered CWE id the kind mapping knows
(`test_a_rule_declaring_two_cwes_gets_one_kind_through_the_adapter_and_the_import`). Semgrep's JSON
keeps a rule's CWE ids in the order the rule declares them and its SARIF writes them sorted, so
`native_cwe` lists the same ids, each path in the order it read them, which is not part of a
claim's identity.

**CodeQL** keeps rules in `driver.rules` or in a query pack under `tool.extensions`, reached by
`rule.toolComponent.index`; indexes `run.artifacts`; links its message to `relatedLocations` ids;
and writes `partialFingerprints`. It groups results by message and primary location by default,
so one result can carry flows from several sources; those are flagged, not split.

## Not done

Rule configuration overrides in an invocation (its notification overrides are read, for execution
evidence only), columns and `columnKind`, `graphs`, `stacks` (other than counting location ids for
message links), `fixes`, and attachments are not read into claims, and a logical-only location names
no file (as a primary location it is a loss). Markdown is never rendered. SARIF other than 2.1.0,
several runs merged into one bundle, and saved vendor formats other than SARIF have no importer.
