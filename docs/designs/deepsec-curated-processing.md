# Curated DeepSec processing (diagnostic)

Issues: [#117](https://github.com/Har1sh-k/scaneval/issues/117) and follow-up
[#124](https://github.com/Har1sh-k/scaneval/issues/124).

Curated processing chooses which regex candidates of a full run DeepSec assigns to
AI batches. It is for investigating one question: given the regex candidates
DeepSec finds anyway, what does its agent report when only the candidates on
chosen paths are assigned a batch? It is opt-in, diagnostic, and never a
benchmark. A curated run is never a `success`, so it completes no control and
earns no quiet credit. It is not a blind full-repository comparison and must not
be reported as one.

## Configuration

`config.process_manifest_by_tree` is an object in the DeepSec system
configuration. Each key is an input tree hash, the `input.tree_hash` of the scan
request, which is the tree the scanner actually receives (for a blinded input,
the blinded tree). Each value is a non-empty array of repository-relative paths.
The map is part of the recorded, digested system configuration. It carries paths
only: no case identifier, label, weakness class, expected result, or reason for
the selection.

The example below is fabricated. Its tree hash and paths name no real corpus.

```json
{
  "system_id": "deepsec-curated-diagnostic",
  "adapter": "deepsec",
  "config": {
    "deepsec_root": "/opt/deepsec-workspace",
    "model": "claude-haiku-4-5",
    "agent": "claude",
    "process_manifest_by_tree": {
      "sha256:1111111111111111111111111111111111111111111111111111111111111111": [
        "src/api/orders.js",
        "src/lib/query-builder.js"
      ]
    }
  }
}
```

Without the key, the adapter runs an ordinary full scan. Adapter version 1.2.0
honors the key. An earlier adapter ignores it and runs unscoped, which is why the
version changed. An experiment frozen against adapter 1.1.0 records that version
in its systems' adapter identity. Frozen matrix execution rejects an
adapter-identity or adapter-version mismatch before creating output or starting
a scanner; the matrix must be deliberately refrozen. With matching adapter
identity, matrix orchestration can proceed. Every matrix cell requires OCI, and
DeepSec is not OCI-compatible, so each cell's runner skips DeepSec before its
prepare phase. No DeepSec scanner invocation or DeepSec execution record is
produced. The matrix output, and any report generated from it, carry skipped
assignments, incomplete cell statuses, and incomplete overall execution, with no
adapter-version-drift reason. Existing 1.1.0 runs and
their replay are not rewritten. Adapter 1.2.1
reads a standard-mode `process` exit 1 from DeepSec's records instead of ending
the run with no claims (#120), so a failed batch's records written before and
after that change carry different versions.

Reports read the same facts from what each run recorded. A run manifest
records every system's adapter version, so `scaneval aggregate` and `scaneval
compare` refuse to pool runs under the same system id when those runs record two
adapter versions; a run that ran nothing for it pools whatever version it
recorded. Runs kept under distinct system ids can be compared across versions,
with `adapter_version` listed as a configuration difference. A curated system is
marked `processing: curated` in their system rows and in the benchmark score's,
with a caveat in every view and in the score's `limits`: its figures describe the
chosen paths and are not a detection rate. Comparing it with a full system lists
`processing` and the key among the configuration differences, so a gate passes
the comparison only when its policy names both. A configuration naming the key
with a recorded adapter before 1.2.0 is marked `full`, with a caveat that the key
was ignored. A result that records the marker itself (see
[What the run reports](#what-the-run-reports)) must agree with the configuration
and the version, or the runs are refused, naming the bundle; a result written
before the marker existed is read from them. No saved artifact is rewritten and no
figure changes.

## What runs

1. `deepsec scan` runs unchanged over the whole supported repository.
2. `deepsec process` runs in standard mode with `--manifest
   raw/deepsec-process-manifest.json`. That file holds exactly the configured
   array for this tree. DeepSec 2.3.10 reads the array into a `Set` and selects a
   pending record for an AI batch when `Set.has(record.filePath)` holds. The match
   is exact, with no normalization and no directory prefix. `--limit` applies after
   that selection, and records it does not select are assigned no batch and stay
   `pending`. Selection decides batch assignment only. It is not a sandbox: the
   agent still runs with the whole repository visible.
3. `deepsec export` runs unchanged. It reads every record and ignores the
   manifest.

The manifest is a raw artifact, and its digest is in the steps note. Because
DeepSec's agent can run a shell in the workspace, the adapter compares the
post-run bytes with the bytes it wrote.

## Refused before anything runs

- A key that is present but malformed: `null`, `{}`, a non-object, a key that is
  not `sha256:` and 64 lowercase hex digits, a value that is not a non-empty
  array, or an item that is not a string. An explicit empty array is refused,
  because it would assign no AI batch.
- An empty path or a duplicate path.
- A path containing NUL. NUL is a filesystem impossibility: no filesystem path can
  contain that byte.
- As separate conservative ScanEval policy, a path containing a non-NUL C0 control
  U+0001-U+001F or DEL U+007F, or beginning or ending with whitespace. The control
  predicate does not reject C1 U+0080-U+009F. A C1 code point that Python treats as
  leading or trailing whitespace still meets the separate edge-whitespace policy;
  an internal C1 code point, or an edge C1 code point Python does not treat as
  whitespace, is not refused by either rule.
- A path containing a lone surrogate or backslash, or one that is absolute, starts
  with a drive letter, or has an empty, `.` or `..` segment (so `./x`, `a//b`, a
  trailing `/`, and traversal). The drive-letter test is any ASCII letter followed
  by `:` at the start, so it also refuses a valid POSIX name such as `a:b`. Paths
  are never rewritten, because the digest has to bind exactly the manifest DeepSec
  reads.
- A request whose tree hash has no entry. The adapter never falls back to an
  unscoped run.
- A listed path that is not a regular file of that tree as spelled, checked
  component by component against directory listings. That covers missing files,
  directories, and case or Unicode-form aliases that a case- or
  normalization-insensitive filesystem would resolve; DeepSec's manifest match is
  exact in either case. Symbolic-link components are also refused because the
  evaluator's tree check deliberately does not follow links: a final link is not
  accepted as a regular file, and a link in a directory
  component is not accepted as that directory. This refusal does not claim which
  spelling DeepSec would record for a followed link.
- A PR request, because DeepSec's direct mode ignores `--manifest`, and
  `config.files_from`, which scopes a PR review.

## What the run reports

Nothing is filtered out of reconciliation. Every record, record status, export
entry, native identity and loss bound counts as it does in an ordinary full run.
The curated run only names populations inside that accounting:

| Population | How it is reported |
| --- | --- |
| Regex records on a listed path | Selected. Only these can be assigned an AI batch. |
| Regex records not listed, left as the scan wrote them | Assigned no AI batch. They stay `pending`, which makes the run `scope_incomplete`, and they are the result's `omitted_paths`: candidates with no assigned verdict, not files shown to be unread. |
| Listed paths for which no readable `FileRecord` has the exact listed `filePath` spelling | After a completed scan, for readable records this can mean no matcher hit, an ignore-filter skip, native discovery did not enumerate the path, or DeepSec recorded the corresponding file under another spelling. For every one of these readable-record possibilities, each affected exact manifest entry selected no readable FileRecord; that fact alone is not a model miss. When the readable record uses another spelling, that same FileRecord may still be selected if the other spelling is also a manifest entry. The run may also have N unreadable DeepSec data records; that count alone does not establish that any is the matching FileRecord. If one is, the absence is import loss and batch assignment cannot be inferred. If the scan failed or was killed, process never ran and no AI batch was assigned, while the cause of the missing exact-spelling readable `FileRecord` remains unknown because the scan was unfinished. |
| Unlisted records with analysis, findings, or a status other than `pending`, and claims on unlisted paths | Kept, and the run fails as `process_manifest_not_honored`. |

The execution note uses the same population definition: listed paths lack a
readable `FileRecord` under the exact listed `filePath` spelling. A completed scan
permits only the bounded account above. An unfinished scan proves that process did
not run and assigned no batch, while the cause of the missing exact-spelling
readable `FileRecord` remains unknown.

Status precedence is unchanged, and two checks are added. The full order is:
timeout, a failed step, an unreadable export, import loss, an exhausted quota
(`quota_exhausted`), failed batches, an undeclared record status, then the new
`process_manifest_not_honored`, then unfinished records (`scope_incomplete`). A
standard-mode `process` exit 1 that the records explain is not a failed step (see
below). The second check applies to a curated
run that reaches the point where it would otherwise succeed: every candidate was
selected, there was no candidate, or the intersection was empty. Such a run is
`partial` with `scope_incomplete`. Every curated run has
`bundles_resolved: false`, so no claim budget or random-order expectation is
read from a selection made before the run. Claims are kept in every `partial`
outcome, so target detection stays visible. A standard-mode `process` exit 1,
which 2.3.10 gives an errored batch or an exhausted quota once every record is
written, does not stop the run before export. It is read from the records like
the rest: a failed selected batch keeps the claims of the batches that finished,
and a run in which no file reached a verdict is an `error`. Only a selected file
left in `error`, or one still `processing` when a run that died was holding it,
explains that exit. An unlisted record is `pending` by design, so it explains
nothing, and an exit 1 with no such record stays `error` with no claims.

`examined_nothing` is not set. The regex scan examined the tree. The notes say
when no AI batch ran, and `partial` already withholds every quiet credit.

Every outcome of a curated run, whatever its status, records `processing:
curated` on its result, a 2.1 field. It is the run's own selection marker, and it
changes no status, claim or credit. A full run records none. A configuration
refused before anything runs (a tree with no entry, a listed path the tree does
not hold) raises before there is an outcome, so the error result the runner
records for it carries no marker.

## Limits

- Selection uses evaluator-side knowledge. Results from it are diagnostics about
  DeepSec's agent on chosen files. They are not detection rates, false-negative
  counts, or a comparison with other systems.
- The manifest holds paths only. It carries no benchmark label, case identifier,
  or reason for the selection.
- Selection assigns AI batches. It does not restrict repository access. The agent
  still sees the whole repository and may read unselected files, for example while
  following an import. `omitted_paths` lists candidates that got no assigned
  verdict. It is not evidence that those files were never read. Network and
  source policy are unchanged.
- A listed path without an exactly spelled readable `FileRecord` has only the
  bounded readable-record explanations in the population table: no matcher hit,
  an ignore-filter skip, native non-enumeration, or an alternate recorded
  spelling. For every one of these readable-record possibilities, each affected
  exact manifest entry selected no readable FileRecord; that fact alone is not a
  model miss. When the readable record uses another spelling, that same FileRecord
  may still be selected if the other spelling is also a manifest entry. The run
  may also have N unreadable DeepSec data records; that count alone does not
  establish that any is the matching
  FileRecord. If one is, the absence is import loss and batch assignment cannot
  be inferred. `.storybook/main.js` is a known DeepSec 2.3.10 non-enumeration
  example from discovery with `dot: false`.
  That example does not establish that every dot-leading path is omitted.
- Exact tree spelling and exact `FileRecord.filePath` spelling can be incompatible
  on a case-insensitive filesystem. In the public issue evidence, the tree path is
  `.GitHub/Workflows/ci.yml`, while DeepSec recorded
  `.github/workflows/ci.yml`. The mixed-case spelling passes the evaluator's exact
  tree check but does not match the record, while the lowercase spelling matches
  the record but fails the evaluator's exact tree check.
  Neither spelling safely satisfies both exact checks.
- Manifest path policy refuses filesystem-impossible NUL, and separately refuses
  non-NUL C0 U+0001-U+001F, DEL U+007F, and leading or trailing whitespace. C1
  U+0080-U+009F is outside the control predicate. The separate edge-whitespace
  policy still refuses a leading or trailing C1 code point that Python treats as
  whitespace. Empty and duplicate paths, lone surrogates, backslashes, absolute
  and drive-letter paths, and empty, `.` or `..` segments are also refused. These
  restrictions can make a real source file unavailable to curated processing.
- Blinded profiles never rename source paths. If a curated path itself contains an
  original identity token, ScanEval refuses that scanner-facing configuration for
  the transformed input; the curated diagnostic is unavailable on that
  transformed input. If the path must be named, use the standard input.
- The fake CLI mirrors only DeepSec 2.3.10's exact
  `Set.has(record.filePath)` manifest predicate, `--limit` after that selection,
  and the exit states the tests explicitly cover. Its scan discovery is
  synthetic: it does not reproduce native dot, ignore, or content matching,
  backslash handling, uppercase-extension or `.env` discovery, or every possible
  record/disk spelling. No live DeepSec, model, or provider has been run with
  this mode.
