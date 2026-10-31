# Curated DeepSec processing (diagnostic)

Issue: [#117](https://github.com/Har1sh-k/scaneval/issues/117).

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
version changed. An experiment frozen against adapter 1.1.0 records that version in
its systems' adapter identity, so executing it with 1.2.0 is refused as version
drift until a new configuration is deliberately frozen, and the matrix report flags
an execution whose adapter differs from the frozen identity as
`adapter_version_drift`. Existing 1.1.0 runs and their replay are not rewritten.
Adapter 1.2.1 reads a standard-mode `process` exit 1 from DeepSec's records
instead of ending the run with no claims (#120), so a failed batch's records
written before and after that change carry different versions.

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

The manifest is a raw artifact, and its digest is in the steps note. Its bytes
are read again after the run, because DeepSec's agent can run a shell in the
workspace.

## Refused before anything runs

- A key that is present but malformed: `null`, `{}`, a non-object, a key that is
  not `sha256:` and 64 lowercase hex digits, a value that is not a non-empty
  array, or an item that is not a string. An explicit empty array is refused,
  because it would assign no AI batch.
- A path DeepSec could not record as written. That covers empty strings,
  duplicates, a NUL byte or any other control character (newline included), a
  lone surrogate, a backslash, an absolute path, a drive letter, leading or
  trailing whitespace, and an empty, `.` or `..` segment (so `./x`, `a//b`, a
  trailing `/`, and traversal). The drive-letter test is any ASCII letter followed
  by `:` at the start, so it also refuses a valid POSIX name such as `a:b`. Paths
  are never rewritten, because the digest has to bind the manifest DeepSec reads.
- A request whose tree hash has no entry. The adapter never falls back to an
  unscoped run.
- A listed path that is not a regular file of that tree as spelled, checked
  component by component against directory listings. That covers missing files,
  directories, symbolic-link components, and case or Unicode-form aliases that a
  case-insensitive filesystem would resolve but DeepSec's exact match would not.
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
| Listed paths with no record | No regex candidate there, or DeepSec's ignore filter skipped the file. No AI batch ran. That is native triage, not a model's miss. This holds only after a completed scan: when the scan fails or is killed, the note says the missing record cannot be attributed. |
| Unlisted records with analysis, findings, or a status other than `pending`, and claims on unlisted paths | Kept, and the run fails as `process_manifest_not_honored`. |

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
- The adapter cannot see DeepSec's ignore filter. A listed path with no record is
  reported as "no candidate or ignored", without saying which.
- A file whose name begins or ends with whitespace cannot be listed.
- The tests use a fake CLI that mirrors the 2.3.10 selection code and its
  standard-mode exit codes. No live DeepSec, model, or provider has been run with
  this mode.
