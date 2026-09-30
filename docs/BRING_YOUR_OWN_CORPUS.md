# Bring your own corpus

This guide documents the organization-owned case pack path as the code implements it today, in
package version `2.0.0a1`. It is the documentation deliverable named in
[design decisions section 9](DESIGN_DECISIONS.md#9-bring-your-own-test-cases).

Examples use a throwaway pack under `/private/tmp/byoc` with a local Git repository as its
snapshot source. Substitute your own paths and commit IDs. Where the design asks for something
the code does not do yet, the gap is stated in the section it belongs to. Section 9 collects
the gaps.

Two conventions used throughout:

```sh
SB=scaneval              # or the path to it inside your virtual environment
BYOC=/private/tmp/byoc   # the organization's working directory
```

JSON output in this guide is wrapped across lines for readability. The commands themselves print
canonical JSON on one line.

Exit codes are the same for every command. `0` means the command ran and reports nothing wrong,
which is not a statement that any label or decision is correct. `1` means the command ran and
reports a negative result, such as a failed mechanical check set or a run that produced no usable
scan. `2` means the command could not be carried out at all.

## 1. What a private pack is

A pack is one JSON file. It holds a namespace, a pack id, a version, a status, pinned snapshots,
case records, and admission decisions. `corpus init` creates one.

| Property | Where it comes from |
|---|---|
| Namespaced | `namespace` matches `^[a-z0-9]+(\.[a-z0-9-]+)*$`, for example `acme.security`. `pack_id` matches `^[a-z0-9][a-z0-9-]*$`. |
| Versioned | `version` is any non-empty string. `status` is `draft`, `reviewed`, or `released`. A pack that is not a draft is refused for edits unless `--new-version` opens a new draft version of it. |
| Pinned | Every snapshot names a repository URL and a full 40-hex commit. The export's content hash (`tree_hash`) is recorded when mechanical checks run against it. |
| Same contract | `src/scaneval/schemas/case-pack.schema.json` is the one contract for public and organization-owned packs. There is no private variant of the schema. |
| Same evaluation | `scaneval plan`, `scaneval run`, `scaneval review`, `scaneval score`, `scaneval replay`, and `scaneval report` do not ask whether a pack is public. Adapters, the observer trace mode, and `scaneval.scoring.score` are shared. |
| Organization controlled | Every file the CLI writes is a local file you name. The only network use is `git fetch` of the snapshot URL you declared and of an adapter's pinned ruleset URL, plus whatever a model-backed adapter does with its provider. |

Nothing in a pack is ever copied into a scanner workspace. The scanner receives a private
workspace copy of one exported source tree and a scan request that carries no labels:

```json
{"input":{"languages":["python"],"mode":"full","profile":"standard","root":".",
          "tree_hash":"sha256:2ae31545c1e6cde1b334fb37c174c5d1071533ead71f95a755a6c86a8ba8c184"},
 "limits":{"timeout_seconds":600},"run_id":"acme-internal-pilot-2026-09-20",
 "schema_version":"2.0","system":{"id":"semgrep-local-rules"},"trace_mode":"off"}
```

Three checks in the code keep pack material out of that tree. `scaneval.cases` never writes
outside the pack. Every command that names a path it may write refuses a path inside a
materialized trial directory, which is recognized by a `provenance.json` file beside a `source`
directory. The runner refuses a scanner workspace that resolves inside the run output, the source
cache, or an exported input.

```
$ $SB plan --pack "$BYOC/pack.json" --snapshot-id reporting-main --tree-hash "$TREE" \
      --output "$BYOC/trials/reporting-main/source/plan.json"
scaneval: refusing to write /private/tmp/byoc/trials/reporting-main/source/plan.json inside the
trial directory /private/tmp/byoc/trials/reporting-main; evaluator plans, packs, and decisions
stay outside an exported input tree
exit=2
```

A pack is not these things:

- Not a scanner input. No command hands a pack, a plan, or a decisions file to an adapter.
- Not a label until a person records one. An import writes a draft case with disposition
  `needs_evidence`, and no code path raises a case past the mechanical state.
- Not a license check. `add-snapshot` always records `license.verified: false`. Only a human edit
  of the pack file may set it true.
- Not a backup system. A pack edit replaces the file through a temporary file and a rename. The
  previous version is not kept. Version history belongs in your own repository.

## 2. The authoring path end to end

The authoring path is: supplied artifact, then candidate and evidence draft, then human
approval, then versioned pack, then evaluation. The commands map onto it directly.

| Step | Command | What it records |
|---|---|---|
| Supplied artifact | `corpus import` | One draft case, one evidence record per artifact, disposition `needs_evidence`, review state `draft`. |
| Candidate and evidence draft | `corpus validate --snapshot-id` | An export of the pinned snapshot plus one L1 check set per case, recorded in the pack. |
| Human approval | `corpus disposition`, `corpus approve`, `corpus admit` | A screening decision, one named review per case, one named admission decision. |
| PR scope, when a change is reviewed | `corpus add-change-set`, `corpus pr-scope`, `corpus canonical` | A declared base/head boundary, and per item whether the PR review scores it. Labels: an approval recorded before does not cover them. |
| Versioned pack | the pack file, `--new-version` | The version and status the plans and manifests then cite by hash. |
| Evaluation | `plan`, `run`, `review`, `replay`, `report` | A plan, a run directory, drafted decisions, recorded review, scores. |

### The worked example

The snapshot source is a local repository holding a small Flask service. `app/handler.py`
concatenates a query parameter into a shell string; `app/safe.py` runs an argument list behind an
allowlist.

```sh
$SB corpus init "$BYOC/pack.json" \
  --namespace acme.security \
  --pack-id internal-pilot \
  --description "Organization-owned pilot pack: one internal service snapshot, four intake forms."
```

```
Created draft pack acme.security/internal-pilot 0.1.0-draft: /private/tmp/byoc/pack.json
```

```sh
COMMIT=$(git -C "$BYOC/reporting-service" rev-parse HEAD)

$SB corpus add-snapshot "$BYOC/pack.json" \
  --snapshot-id reporting-main \
  --url "$BYOC/reporting-service" \
  --name acme/reporting-service \
  --commit "$COMMIT" \
  --language python \
  --workload conventional_application \
  --component-role application \
  --reference "parent of internal fix PR-4821; pinned from the organization mirror" \
  --license-spdx LicenseRef-acme-internal
```

```
Added vulnerable snapshot reporting-main at 8cfdba14ed72; license verified: false
```

`--language` is repeatable and accepts `python`, `typescript`, `javascript`, `go`, `rust`.
`--workload` accepts `conventional_application`, `conventional_automation`,
`ai_assisted_application`, `agentic_application`. `--component-role` accepts `application`,
`library_sdk`, `infrastructure`. `--role` accepts `vulnerable` (the default), `fixed`, `ordinary`.

Then one import per supplied artifact. Section 3 covers the three forms. For a finding, save a
JSON object such as this in `$BYOC/finding.json`, using a path and lines from your snapshot:

```json
{"allegation":"An unauthenticated reporting request controls a shell command.",
 "path":"src/app.py","start_line":5,"end_line":5,"kind":"command_injection",
 "source":"internal security review"}
```

```sh
$SB corpus import "$BYOC/pack.json" \
  --case-id acme-report-shell \
  --snapshot-id reporting-main \
  --represents "This case tests shell command construction from an HTTP query parameter under the assumption that the reporting endpoint is reachable by unauthenticated users, and adds the organization's only process-execution mechanism in a Flask handler." \
  --workload conventional_application --component-role application \
  --finding "$BYOC/finding.json"
```

```
Imported draft case acme-report-shell: 1 evidence records, disposition needs_evidence, review state draft, level None
```

`corpus validate` with no `--snapshot-id` schema-checks the pack and prints a summary:

```sh
$SB corpus validate "$BYOC/pack.json"
```

The summary reports the namespace, pack id, version, status, snapshot and case counts,
disposition and review-state counts, and the pack hash. The import above adds one draft case
with disposition `needs_evidence`; it grants no approval.

With `--snapshot-id` it fetches the commit into an immutable cache, exports it into a new trial
directory, and runs the L1 checks:

```sh
$SB corpus validate "$BYOC/pack.json" \
  --snapshot-id reporting-main \
  --cache-root "$BYOC/.repos" \
  --trial-root "$BYOC/trials"
```

For example, a pack with two imported findings, a fix reference, and an incident document
can report the following. References without source locations do not pass the location check:

```
scaneval: mechanical checks failed for 2 case(s): acme-report-fix, acme-report-incident; the results are recorded in the pack
Exported reporting-main to /private/tmp/byoc/trials/reporting-main (sha256:2ae31545c1e6cde1b334fb37c174c5d1071533ead71f95a755a6c86a8ba8c184)
acme-report-shell: pass (mechanically_checked, level L1)
acme-report-fix: fail (draft, level None); failed: locations_exist_in_snapshot
acme-report-allegation: pass (mechanically_checked, level L1)
acme-report-incident: fail (draft, level None); failed: locations_exist_in_snapshot
exit=1
```

The exported tree and its provenance sit side by side. This is the trial directory the path check
in section 1 recognizes:

```
trials/reporting-main/provenance.json
trials/reporting-main/source/README.md
trials/reporting-main/source/app/handler.py
trials/reporting-main/source/app/safe.py
```

Then the human decisions, one command each:

```sh
$SB corpus disposition "$BYOC/pack.json" --case-id acme-report-shell --value validate \
  --reason "Root cause, affected input, and deployment assumptions are established; proceed to label validation."

$SB corpus approve "$BYOC/pack.json" --case-id acme-report-shell \
  --reviewer "P. Adeyemi" --role curator --level L2 \
  --note "Handler parses; the shell call and the query parameter were read in the exported tree."

$SB corpus approve "$BYOC/pack.json" --case-id acme-report-shell \
  --reviewer "R. Mehta" --role independent_reviewer --level L3 \
  --note "Independent read of handler.py confirms the query parameter reaches the shell string."

$SB corpus admit "$BYOC/pack.json" --case-id acme-report-shell --decision admitted \
  --by "S. Okafor" --reason "Distinct process-execution mechanism; independent review recorded."
```

Each prints the record it appended, for example:

```json
{"at":"2026-09-20T20:42:31+00:00","decision":"approve","level":"L3",
 "note":"Independent read of handler.py confirms the query parameter reaches the shell string.",
 "reviewer":"R. Mehta","role":"independent_reviewer"}
```

The versioned-pack step is the pack file itself. Nothing in the CLI moves a pack from `draft` to
`reviewed` or `released`; that is an edit you make in the pack file and commit to your own
repository. Once the status is not `draft`, every pack-changing command refuses the pack until
`--new-version` opens a new draft version of it:

```
$ $SB corpus disposition "$BYOC/pack-released.json" --case-id acme-report-incident --value exclude --reason "..."
scaneval: pack status is released, not draft; changing it needs --new-version <version>, which opens a new draft version of this pack
exit=2

$ $SB corpus disposition "$BYOC/pack-released.json" --case-id acme-report-incident --value exclude --reason "..." --new-version 1.1.0-draft
{"reason":"Out of scope: the document names no in-scope source.","value":"exclude"}
exit=0

$ jq -r '"\(.version) \(.status)\n\(.notes[-1])"' "$BYOC/pack-released.json"
1.1.0-draft draft
version 1.0.0 (status released) reopened as 1.1.0-draft (status draft)
```

Reopening re-checks nothing, approves nothing, and withdraws no recorded review or admission.

The evaluation step is section 6.

## 3. The three intake forms

`corpus import` takes exactly one artifact flag. The three are mutually exclusive and one is
required:

```
scaneval corpus import: error: one of the arguments --fix-commit --finding --document is required
```

| Flag | Evidence `origin` | Evidence `kind` | `reference` | Accepted locations |
|---|---|---|---|---|
| `--fix-commit SHA --repo URL` | `fix_without_advisory` | `fix_commit` | `<repo>@<sha>` | none |
| `--finding FILE` | `research_note` | `scanner_allegation` | the file path | one location from the allegation's `path` and optional line pair, role `other`, note `imported allegation, not a reviewed label` |
| `--document FILE [--section S]` | `research_note` | `internal_document` | the file path | none |

Every form writes the same case shell: review state `draft`, level `null`, disposition
`needs_evidence` with a reason naming the artifact, every coverage-signature field
`{"state": "not_reviewed"}`, and `split: unassigned`.

The evidence notes are written by the tool and state what it did not do:

```json
{"evidence_id":"fix-commit","origin":"fix_without_advisory","kind":"fix_commit",
 "reference":"/private/tmp/byoc/reporting-service@0000000000000000000000000000000000000000",
 "note":"Supplied fix commit. The CLI did not fetch, read, or verify it."}

{"evidence_id":"allegation","origin":"research_note","kind":"scanner_allegation",
 "reference":"/private/tmp/byoc/finding.json",
 "note":"Allegation from acme-internal-scanner 3.4, imported verbatim. An allegation is not a reviewed label."}

{"evidence_id":"document","origin":"research_note","kind":"internal_document",
 "reference":"/private/tmp/byoc/incident-note.md",
 "note":"section 3. Supplied document, recorded as a reference and not read by the CLI."}
```

Stated plainly:

- Importing a scanner allegation does not validate it. The allegation's path becomes a candidate
  location and its text becomes the case description. Nothing reads the code, and the disposition
  stays `needs_evidence` until a person changes it.
- A closed ticket is not a negative label. There is no import form that produces a control. A
  control record must be written into the pack by hand, with its property, allowed actors and
  inputs, assumptions, ruled-out allegation, locations, and evidence ids, and the same review
  requirements then apply to it.
- A repository reference is not evidence about code. `--fix-commit` records a string. The commit
  is not fetched, and the one commit the tool does fetch is the snapshot commit named in
  `add-snapshot`.

Two details that matter for internal material:

- `--alias` takes the identifiers your organization already uses. An internal ticket or review
  id passes the L1 check `aliases_well_formed` unchanged, because a CVE is neither required nor
  sufficient for a case. An identifier that begins with `CVE` or `GHSA` is held to the public
  shape, so a typo in a published id is caught rather than carried into the pack:

  ```
  acme-alias-probe: fail (draft, level None); failed: CVE-2026-1 is not a well formed CVE or GHSA identifier
  ```

- A supplied allegation must carry `allegation` and `path`. `start_line` and `end_line` must be
  supplied together and each must be an integer of at least 1; anything else is refused rather
  than guessed at. A missing pair leaves the imported location file-only.

## 4. Review states and what L1 actually checks

A case carries `validation.review_state` and `validation.level`.

| Review state | Level | How it is reached |
|---|---|---|
| `draft` | `null` | Import, or a referenced snapshot without a recorded passing check set. |
| `mechanically_checked` | `L1` | Every snapshot the case references has a recorded passing L1 check set. Written by code only. |
| `human_approved` | `L2`, `L3`, or `L4` | One `corpus approve` call naming a reviewer. Never written by any other path. |

`corpus validate --snapshot-id` runs six checks per case, per snapshot, and records them in the
pack with the snapshot id attached:

| Check | What it reads |
|---|---|
| `locations_exist_in_snapshot` | Declared location paths against an exact listing of the exported tree. A case with no declared location fails with `no locations declared`. |
| `line_ranges_within_files` | `end_line` against the newline count of the file. File bytes are read only to count lines. |
| `aliases_well_formed` | Each alias is non-blank, and one that begins with CVE or GHSA matches the published identifier shape. Internal identifiers pass. |
| `represents_statement` | That `represents` matches `This case tests ... under ..., and adds ...`. |
| `evidence_recorded` | That at least one evidence record exists. |
| `snapshot_hash_recorded` | That the pack's recorded tree hash for the snapshot agrees with this export. |

Nothing here parses source, establishes a root cause, infers a reviewer, or approves anything, so
no check raises a case past L1. Checks are recorded per snapshot, so a case spanning a vulnerable
and a fixed snapshot reaches L1 only after every snapshot it references has passed.

Only an explicitly named human reviewer can raise a case beyond L1. `corpus approve` requires
`--reviewer`, `--role`, `--level`, and `--note`, and it refuses:

```
$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-shell --reviewer "   " --role curator --level L2 --note "x"
scaneval: approval requires an explicit reviewer name; the tool never supplies one
exit=2

$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-fix --reviewer "R. Mehta" --role independent_reviewer --level L3 --note "x"
scaneval: case acme-report-fix has not passed mechanical checks; run corpus validate first
exit=2

$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-shell --reviewer "P. Adeyemi" --role curator --level L3 --note "x"
scaneval: L3/L4 labels require an independent_reviewer decision
exit=2

$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-allegation --reviewer "R. Mehta" --role independent_reviewer --level L3 --note "x"
scaneval: L3/L4 require disposition validate
exit=2
```

The first refusal is checked before anything else, so an unnamed approval is refused whatever
state the case is in. The second case is `draft`, the third is approved at L3 already, and the
fourth is `mechanically_checked` with disposition `exclude`.

So L3 and L4 need both an `--role independent_reviewer` decision and disposition `validate`. The
pack contract enforces the same two rules on every write, which is why a disposition change that
would leave an approved L3 case off `validate` is refused and the pack is left unchanged:

```
$ $SB corpus disposition "$BYOC/pack.json" --case-id acme-report-shell --value needs_evidence --reason "reopening"
scaneval: case acme-report-shell: L3 requires disposition validate, not needs_evidence
exit=2
```

The reviewer name is stored verbatim. The tool does not authenticate the reviewer, check their
independence, or verify that anything was read. `--role independent_reviewer` records a claim
about who decided, not a verified separation of duties. `corpus approve` records a claim of review;
it does not establish the label.

Code never withdraws a human review. When a check set fails for an already approved case, the
review state and level stay exactly as the reviewer left them, `validation.checks_failed` is set,
and `build_plan` leaves that case out with a note until a correction decision resolves it. Re-running
the checks on an approved case reports its recorded state unchanged:

```
acme-report-shell: pass (human_approved, level L3)
```

## 5. Dispositions and admission

A disposition is a screening decision about whether a candidate is worth validating. It is not a
label, an approval, or an admission.

| Disposition | Meaning | Effect on planning |
|---|---|---|
| `validate` | Credible evidence and a useful contribution justify label validation. | Planned when the checks pass and a level is recorded. Required for L3 and L4. |
| `needs_evidence` | Plausible, but source, assumptions, or root-cause evidence is incomplete. | Still planned when the checks pass, at whatever level is recorded. That level cannot be L3 or L4, so a plan containing such a case has scope `draft`. |
| `extended_regression` | Validated but redundant for the main release. | Planned exactly like any other non-excluded case. The code does not separate it. |
| `exclude` | Outside scope or contradicted by the evidence. | Left out of every plan, with the reason in the plan notes. |

```
note: acme-report-allegation: excluded by disposition (Same root cause as acme-report-shell; kept as a duplicate record, not a second target.)
```

`corpus disposition` requires a non-blank `--reason` and appends the change to the case notes, so
the previous value stays visible:

```
disposition changed from needs_evidence to validate: Root cause, affected input, and deployment assumptions are established; proceed to label validation.
```

`corpus admit` appends one admission decision. `--decision` accepts `admitted`, `rejected`, or
`deferred`. `--by` and `--reason` must both be non-blank.

| Admission | Effect on planning |
|---|---|
| no admission record at all | The case is planned. Admission is recorded, not required. |
| `admitted` | The case is planned. |
| `deferred` | The case is planned. Only `rejected` removes a case. |
| `rejected` as the latest record for that case | The case is left out, with the reason in the plan notes. |

Ordering is list order. Timestamps are recorded text and are not parsed or sorted. An admission
never changes a case's review state or level.

Gap against the design: the design treats admission as a release gate. The code treats it as a
record, and a case with no admission decision is planned like any other. If your process requires
admission before evaluation, enforce it by checking the pack, not by relying on the planner.

## 6. Running an evaluation on the pack

### The run configuration

`scaneval run CONFIG --output DIR` executes one frozen configuration. The contract is
`src/scaneval/schemas/run-config.schema.json` at 2.0 and `run-config-2.1.schema.json` at 2.1.

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | `"2.0"` or `"2.1"`. Fields marked 2.1 below need `"2.1"`. |
| `run_id` | yes | Matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`. |
| `pack` | yes | Path to the case pack, relative to the configuration file. |
| `cache_root` | no | Immutable source cache, relative to the configuration file. Default `.repos`. |
| `inputs[].snapshot_id` | yes for a full input | A snapshot the pack declares. Refused before anything is written otherwise. A PR input names no snapshot; see [a native PR input](#a-native-pr-input). |
| `inputs[].input_id` | no, 2.1 | Names the input's directory and invocations; never shown to a scanner. Defaults to the snapshot id, with `.blinded` appended for a blinded input. |
| `inputs[].mode` | no, 2.1 | `full` (default) or `pr`. A `pr` input reviews a change and names its `change_set_id`; a full scan of the head never stands in for one. |
| `inputs[].change_set_id` | 2.1, PR input | A change set the pack declares. Required when `mode` is `pr`, and refused for a full input. Refused before anything is written when the pack does not declare it. The input's default `input_id` is this id. |
| `inputs[].profile` | no | `standard` (default) or `metadata_blinded`, which needs a 2.1 configuration; see [a metadata-blinded input](#a-metadata-blinded-input). |
| `inputs[].blinding_map` | 2.1 | Path to the reviewed blinding map, relative to the configuration file. Required exactly when `profile` is `metadata_blinded`. |
| `systems[].system_id` | yes | Matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`. |
| `systems[].adapter` | yes | `semgrep`, `llm-harness`, or `deepsec` in this build. |
| `systems[].config` | yes | Adapter configuration. For `semgrep` this pins a rules repository by url, commit, and paths; for `deepsec` it names the installed workspace and the model. See the [example configuration](../corpus/pilot/run-deepsec.json). |
| `systems[].model_id`, `model_revision` | no | Recorded in the scan request and the execution record. |
| `systems[].network_policy` | no | Overrides the run-level policy for this system. |
| `systems[].execution` | no, 2.1 | `{"backend": "local"}` by default. A system configured for another backend is recorded as skipped, with the reason, rather than run without it. |
| `repetitions` | yes | Integer of at least 1. |
| `timeout_seconds` | yes | Number greater than 0. |
| `trace_mode` | yes | `off`, `metadata`, or `content`. |
| `network_policy` | yes | `none`, `model_provider_only`, or `unrestricted`. Recorded, not enforced. |
| `notes` | no | Free text carried into the run. |

A working configuration, pinned to a local rules checkout:

```json
{
  "schema_version": "2.0",
  "run_id": "acme-internal-pilot-2026-09-20",
  "pack": "pack.json",
  "cache_root": ".repos",
  "inputs": [{"snapshot_id": "reporting-main", "profile": "standard"}],
  "systems": [
    {"system_id": "semgrep-local-rules", "adapter": "semgrep",
     "config": {"ruleset": {"url": "/private/tmp/byoc/rules",
                            "commit": "b004788273809142d1505d0b25d11654de79daab",
                            "paths": ["python"]},
                "rule_timeout_seconds": 30, "jobs": 2},
     "network_policy": "none"}
  ],
  "repetitions": 1,
  "timeout_seconds": 600,
  "trace_mode": "off",
  "network_policy": "none",
  "notes": ["Local rules checkout and local source mirror; no network fetch."]
}
```

```sh
$SB validate run-config "$BYOC/run-local.json"
mkdir -p "$BYOC/workspaces"
$SB run "$BYOC/run-local.json" --output "$BYOC/runs/2026-09-20" --workspace-root "$BYOC/workspaces"
```

```
reporting-main__semgrep-local-rules__r1 status=success claims=1 plan=reviewed review=draft
Manifest: /private/tmp/byoc/runs/2026-09-20/run-manifest.json
Schedule: /private/tmp/byoc/runs/2026-09-20/evaluator/schedule.json
```

`--output` must not exist. `--workspace-root` must exist and must resolve outside the run output,
the source cache, and every exported input; a workspace root that does not exist fails the run.
`--only-input` (input ids) and `--only-system` narrow the run and are refused when they name
something the configuration does not contain. What was narrowed away is recorded in the manifest's
`selection` and in the schedule's notes.

`run` exits `1`, not `0`, when any input could not be prepared, when any invocation ended in
`error`, `timeout`, or `skipped`, or when the manifest status is not `completed`. The bundles it
did produce are still there.

### The run directory

```
runs/2026-09-20/
  run-config.json                      canonical copy of the configuration that was executed
  run-manifest.json                    what ran, what was skipped, where every artifact landed
  evaluator/schedule.json              every assignment, pre-registered plan, and pair, frozen first
  evaluator/pack.json                  the pack copy this run froze, with its check results
  inputs/reporting-main/provenance.json
  inputs/reporting-main/source/        the exported tree
  invocations/reporting-main__semgrep-local-rules__r1/
    request.json                       sanitized scan request, no labels
    result.json                        normalized claims with explicit status
    execution.json                     exit status, timing, versions, policy, capture, provenance
    evaluation.json                    scores for this invocation
    report.html                        standalone HTML report for this invocation
    raw/                               stdout, stderr, native artifacts
    evaluator/plan.json
    evaluator/decisions.json
    evaluator/review-record.json
```

`trace/` appears in the bundle as well when `trace_mode` is not `off`. An input's directory is
named by its input id, which for a 2.0 configuration is its snapshot id. The invocation id is
`<input id>__<system>__r<repetition>`; a configuration whose ids would collide is refused before
the output directory is created.

A bundle that carries a trace answers one question the scores do not. `scaneval diagnose
context-coverage <bundle>` reports, per labeled target, whether that target's code region was
supplied to the model and in which invocation. It reads your pack's `accepted_locations` and the
trace's `context.selection` spans, joins them evaluator-side after the run, writes nothing into
the bundle, and reaches no metric: a target whose code was never supplied is still a target the
scan did not detect. See [diagnostics](DIAGNOSTICS.md) for the classification table and for what
the document refuses to claim.

The run never edits the source pack on disk. Its mechanical check results land only in the frozen
copy at `evaluator/pack.json`, which is written once, after every input is prepared and before the
first invocation. That frozen copy is the pack a later `review init` must be given, because the
re-run checks give the frozen copy a different hash from the pack file on disk.

`evaluator/schedule.json` is written before the first input is fetched, so nothing the run
observes can change what it was assigned. It lists every assignment under the invocation id its
bundle will carry, the plan the pack gives each input before execution when the snapshot already
declares its tree hash, and the vulnerable/fixed pairs matched in advance. An assignment that later
fails stays in it, and in every denominator built from it.

An input that cannot be prepared is recorded against that input, and the run goes on without it:
its assignments become skipped invocations naming the failure, no scanner is called for it, and
`run` exits `1`. Here a second snapshot pins a commit the mirror no longer has:

```
$ $SB run "$BYOC/run-gone.json" --output "$BYOC/runs/gone" --workspace-root "$BYOC/workspaces"
reporting-main__semgrep-local-rules__r1 status=success claims=1 plan=draft review=draft
reporting-gone__semgrep-local-rules__r1 status=skipped claims=None plan=None review=None
Manifest: /private/tmp/byoc/runs/gone/run-manifest.json
Schedule: /private/tmp/byoc/runs/gone/evaluator/schedule.json
scaneval: input reporting-gone could not be prepared: MaterializationError: git checkout -q --detach 0000000000000000000000000000000000000001 failed (128): fatal: unable to read tree (0000000000000000000000000000000000000001)
scaneval: no usable scan from 1 invocation(s): reporting-gone__semgrep-local-rules__r1
exit=1

$ jq -c '{status, schedule_path}' "$BYOC/runs/gone/run-manifest.json"
{"status":"completed","schedule_path":"evaluator/schedule.json"}

$ jq -c '[.assignments[].assignment_id]' "$BYOC/runs/gone/evaluator/schedule.json"
["reporting-gone__semgrep-local-rules__r1","reporting-main__semgrep-local-rules__r1"]
```

The manifest's row for `reporting-gone` carries `preparation_failure` with that type and message,
and null tree and input hashes. Its plan in the schedule is `unavailable`, because the snapshot
declared no tree hash before the run. Any other failure once the output directory exists, an
interrupt included, leaves a manifest with status `failed`.

### Draft scope

A plan's scope is `reviewed` only when every planned case is `human_approved` at L3 or L4.
Anything else is a `draft` plan, and the runner writes only machine-drafted decisions, all
`unresolved`. Detection credit is therefore zero by construction on that path.

Run against a pack whose only case is `mechanically_checked`:

```
reporting-main__semgrep-local-rules__r1 status=success claims=1 plan=draft review=draft
```

```json
{"scope":"draft",
 "metrics":{"targets_assigned":1,"targets_detected":0,"known_target_recall":0.0,"pending_matching_count":1},
 "warnings":["Draft labels (not independently reviewed): pipeline diagnostics, not benchmark evidence.",
             "Unresolved target matches earn no confirmed detection credit.",
             "Random-order expectation is not native prioritization or a promotion metric."]}
```

The bundle's `report.html` carries both banners:

```
Draft labels. Targets and controls come from a draft plan and are not independently reviewed;
matching decisions may be unreviewed. Use for pipeline diagnostics only, not as benchmark evidence.

Decisions: machine-drafted, all unresolved; no human review recorded.
```

A reviewed plan behaves the same way until a person resolves the decisions. The reviewed run above
reported `plan=reviewed review=draft`, `targets_detected: 0`, and `pending_matching_count: 1`. The
plan's scope says the labels were reviewed. It says nothing about whether the matching was.

`scaneval plan` builds the same plan outside a run, which is useful for seeing what would be
planned before spending a scan:

```sh
$SB plan --pack "$BYOC/pack.json" --snapshot-id reporting-main --tree-hash "$TREE" \
  --output "$BYOC/plan-reviewed.json" --mode full
```

`--mode pr` on its own changes exactly one thing: the plan carries the pack's `pr` review budgets
instead of its `full` budgets, and records `"mode": "pr"` in its provenance. It is still a full plan
of the snapshot, and says so on stderr, because it names no change. With `--change-set-id` and the
hashes that identify the input it is the plan of that change set's PR review; see
[a native PR input](#a-native-pr-input).

### A metadata-blinded input

The `metadata_blinded` profile scans a copy of a snapshot in which reviewed identity tokens are
replaced in documentation and display metadata only. It is for measuring whether those cues change
a result, not for hiding a repository: package names, imports, identifiers, paths, and code are
never changed, and every blinded export counts the cues that remain. It needs a blinding map, a
JSON document you write, review, and keep beside the pack, never in the snapshot.

The hashes in this subsection come from the snapshot it was verified against, a service whose
README, operations guide, and documentation site name the product `Acme`.

**Write the map from the export.** `corpus validate --snapshot-id` left the snapshot's export in
the trial directory. Each edit names one file, its role, why nothing reads it at runtime, the
tokens it replaces, and for every snapshot the map covers the file's hash and how often each token
occurs in it. Count occurrences, not lines:

```sh
cd "$BYOC/trials/reporting-main/source"
shasum -a 256 README.md docs/operations.md mkdocs.yml
grep -o Acme README.md | wc -l
```

```json
{
  "schema_version": "2.1",
  "map_id": "acme-reporting-service",
  "map_version": "1",
  "repository": {"url": "/private/tmp/byoc/reporting-service", "name": "acme/reporting-service"},
  "pseudonyms": [{"original": "Acme", "replacement": "Example"}],
  "variants": [{"snapshot_id": "reporting-main", "commit": "e17a377ddff4d3c518616a53e56eb0b5cba57c56",
                "tree_hash": "sha256:c267ead9104da0a1e104157b180244efa8aaf74faf9e49c615456386759129bd"}],
  "edits": [
    {"edit_id": "readme-title", "path": "README.md", "role": "non_runtime_branding",
     "rationale": "The README title and first paragraph name the product; nothing reads the README at runtime.",
     "replacements": ["Acme"],
     "expected": [{"snapshot_id": "reporting-main", "state": "present",
                   "file_sha256": "sha256:f9a6a048580372be907b00e460f13b8ee08cd76129a5a3486732c3e08af81bf1",
                   "occurrences": {"Acme": 2}}]},
    {"edit_id": "operations-title", "path": "docs/operations.md", "role": "documentation_identifier",
     "rationale": "The operations guide names the service in its heading.",
     "replacements": ["Acme"],
     "expected": [{"snapshot_id": "reporting-main", "state": "present",
                   "file_sha256": "sha256:1108725d3d07885823d4f2ed8eec118b3bd0963264617de6155e6b1dc103bf12",
                   "occurrences": {"Acme": 1}}]},
    {"edit_id": "docs-site-name", "path": "mkdocs.yml", "role": "display_metadata",
     "rationale": "site_name titles the rendered documentation site.",
     "role_check": "mkdocs reads site_name only to title rendered pages; the service never reads mkdocs.yml.",
     "replacements": ["Acme"],
     "expected": [{"snapshot_id": "reporting-main", "state": "present",
                   "file_sha256": "sha256:be7784f5e35e7585c64c00af5f4eea4f56f2ee287e964fa8c39b4e8e76ac95fe",
                   "occurrences": {"Acme": 1}}]}
  ],
  "reviews": []
}
```

`repository.url` must be the snapshot's URL exactly, and each variant's `tree_hash` is the tree
hash the pack records for that snapshot. A map for a vulnerable and a fixed snapshot of one
repository lists both as variants, and each edit then states an expectation for each, with
`"state": "absent"` where the file does not exist; related snapshots in one run must be blinded
with the same map. Documentation files may be edited under any role. `.yml`, `.yaml`, `.toml`,
`.json`, `.cfg`, and `.ini` files may be edited only as `display_metadata` with a `role_check`.
License and security files, dependency manifests, build, CI, and security configuration, files a
scanner reads as instructions, and every other file, source included, are refused. [Current
capabilities](INITIAL_BUILD.md#metadata-blinding) lists every rule.

**Check it before anyone reviews it.** `blinding check` fetches each variant, applies the map in a
temporary directory exactly as a run would, and reports approval instead of requiring it:

```
$ $SB validate blinding-map "$BYOC/reporting-map.json"
Valid blinding-map: /private/tmp/byoc/reporting-map.json

$ $SB blinding check "$BYOC/reporting-map.json" --pack "$BYOC/pack.json" --cache-root "$BYOC/.repos"
Map acme-reporting-service 1: sha256:b315c4dad24b58ae933d84c0d953d0f0dee31d1a622dcfdbb8232592071c5463; content sha256:fc626885d14212555e2cb4873e53b0d04605c8340dd2b8618a15c1af273f3121
approval: not approved: map acme-reporting-service 1 is unreviewed: no review is recorded
reporting-main: pass; original sha256:c267ead9104da0a1e104157b180244efa8aaf74faf9e49c615456386759129bd, transformed sha256:87c31d4b42b1b3e634b36c82653998362e168d878b3fbf7bf4406b168b9bbe61
  readme-title README.md: Acme=2; changed line(s): 1, 3
  operations-title docs/operations.md: Acme=1; changed line(s): 1
  docs-site-name mkdocs.yml: Acme=1; changed line(s): 1
  17 check(s) passed; retained identity cues: 1 token(s), 2 occurrence(s) in 2 file(s); instruction files: none
  retained in: LICENSE (1), app/handler.py (1)
scaneval: blinding map is not approved; a run refuses it
exit=1
```

The two retained cues are the copyright line and a header name in the handler. Neither can be
edited, so both stay and are recorded. A wrong count or a file the rules refuse is reported per
variant, and the map is never written:

```
reporting-main: refused: blinding map refused: edit readme-title: README.md: unexpected occurrence count in snapshot reporting-main: the map reviewed {'Acme': 1}, the file holds {'Acme': 2}
reporting-main: refused: blinding map refused: edit license-holder: LICENSE is a license, attribution, or security file
```

**Record the review.** A run applies a map only while its latest review approves the map's content
as it stands. `blinding review` appends one chained review naming the reviewer you supply, and
refuses a blank one:

```sh
$SB blinding review "$BYOC/reporting-map.json" --reviewer "Example Reviewer (fictional)" \
  --role independent_reviewer --decision approve \
  --note "Read every edit against the export; the README, operations guide, and site name carry no runtime role."
```

```json
{"at":"2026-09-30T01:19:25+00:00","chain_sha256":"sha256:f4a005311741501ad959168eb042acedb5899fcfba905bdfb71caebf3f111644",
 "content_sha256":"sha256:fc626885d14212555e2cb4873e53b0d04605c8340dd2b8618a15c1af273f3121","decision":"approve",
 "note":"Read every edit against the export; the README, operations guide, and site name carry no runtime role.",
 "reviewer":"Example Reviewer (fictional)","role":"independent_reviewer"}
```

The review covers `content_sha256`, the map without its reviews. Any later edit to the map leaves it
unapproved until someone reviews it again, and `--decision reject` or `unresolved` withdraws an
approval explicitly. As with `corpus approve`, the name is recorded, not verified.

**Run it.** A blinded input needs a 2.1 configuration that names its map, relative to the
configuration file. It can sit beside the standard input of the same snapshot:

```json
{
  "schema_version": "2.1",
  "run_id": "internal-pilot-blinded-2026-09-29",
  "pack": "pack.json",
  "cache_root": ".repos",
  "inputs": [{"snapshot_id": "reporting-main"},
             {"snapshot_id": "reporting-main", "profile": "metadata_blinded",
              "blinding_map": "reporting-map.json"}],
  "systems": [
    {"system_id": "semgrep-local-rules", "adapter": "semgrep",
     "config": {"ruleset": {"url": "/private/tmp/byoc/rules",
                            "commit": "01cb9aa62f15daead361b331b4befdd2503fff83",
                            "paths": ["python"]},
                "rule_timeout_seconds": 30, "jobs": 2},
     "network_policy": "none"}
  ],
  "repetitions": 1,
  "timeout_seconds": 600,
  "trace_mode": "off",
  "network_policy": "none",
  "notes": ["Local rules checkout and local source mirror; no network fetch."]
}
```

A scanner is told its run id, system id, model, and configuration, and it runs in a workspace, beside
a source cache, whose absolute paths it can read. A run in which any of them names an original
token, ignoring case, is refused before anything is written, and that includes the workspace root,
the cache root, and the directory the configuration sits in (each as named and as resolved). A run
id like the one this guide used earlier, `acme-internal-pilot-2026-09-20`, names the company:

```
$ $SB run "$BYOC/run-leaky.json" --output "$BYOC/runs/leaky" --workspace-root "$BYOC/workspaces"
scaneval: the run id names 'Acme', an original identity token of blinding map acme-reporting-service, which would reach the scan of blinded input reporting-main.blinded; rename it, or leave that input standard
exit=2
```

With a neutral run id both inputs run:

```
$ $SB run "$BYOC/run-blinded.json" --output "$BYOC/runs/blinded" --workspace-root "$BYOC/workspaces"
reporting-main__semgrep-local-rules__r1 status=success claims=1 plan=draft review=draft
reporting-main.blinded__semgrep-local-rules__r1 status=success claims=1 plan=draft review=draft
Manifest: /private/tmp/byoc/runs/blinded/run-manifest.json
Schedule: /private/tmp/byoc/runs/blinded/evaluator/schedule.json
```

The blinded input's directory holds the original export under `original/source`, evaluator-side,
and the transformed tree under `source`; a scanner is handed a copy of `source` only. The
preparation record says what changed and what did not:

```
$ jq -c '.blinding | {edits: [.edits[] | {path, changed_lines, occurrences}], retained_identity_cues}' \
    "$BYOC/runs/blinded/inputs/reporting-main.blinded/provenance.json"
{"edits":[{"path":"README.md","changed_lines":[1,3],"occurrences":{"Acme":2}},{"path":"docs/operations.md","changed_lines":[1],"occurrences":{"Acme":1}},{"path":"mkdocs.yml","changed_lines":[1],"occurrences":{"Acme":1}}],"retained_identity_cues":{"instruction_files":[],"path_count":2,"paths":[{"count":1,"path":"LICENSE"},{"count":1,"path":"app/handler.py"}],"token_count":1,"total_occurrences":2}}
```

Lines and paths map to the original as the identity, so the labels written against
`reporting-main` score the blinded input unchanged: the mechanical checks and the declared tree
hash are asked of the original export, while the request, the result, and the plan's input hash
bind to the transformed tree. The plan and the execution record name the map:

```
$ jq -c '{input_hash, provenance: {profile: .provenance.profile, source_tree_hash: .provenance.source_tree_hash, blinding: .provenance.blinding}}' \
    "$BYOC/runs/blinded/invocations/reporting-main.blinded__semgrep-local-rules__r1/evaluator/plan.json"
{"input_hash":"sha256:87c31d4b42b1b3e634b36c82653998362e168d878b3fbf7bf4406b168b9bbe61","provenance":{"profile":"metadata_blinded","source_tree_hash":"sha256:c267ead9104da0a1e104157b180244efa8aaf74faf9e49c615456386759129bd","blinding":{"map_id":"acme-reporting-service","map_sha256":"sha256:bdf1c85df1267444e70b124ae4775b444b1970e1ad7a13d4c634dc98da205a66","map_version":"1"}}}
```

A map that is not approved or no longer fits the export fails that input alone, before any scanner
sees it. After the README edit's rationale is reworded without a new review, the same run reports:

```
reporting-main__semgrep-local-rules__r1 status=success claims=1 plan=draft review=draft
reporting-main.blinded__semgrep-local-rules__r1 status=skipped claims=None plan=None review=None
Manifest: /private/tmp/byoc/runs/edited/run-manifest.json
Schedule: /private/tmp/byoc/runs/edited/evaluator/schedule.json
scaneval: input reporting-main.blinded could not be prepared: MaterializationError: blinding map refused: map acme-reporting-service 1: the latest approval, by Example Reviewer (fictional) (independent_reviewer) at 2026-09-30T01:19:25+00:00, covers content sha256:fc626885d14212555e2cb4873e53b0d04605c8340dd2b8618a15c1af273f3121, but the map now hashes to sha256:87ca782566c26b6dba8d889e80f6c93040d242867b4fd5370d75e5ce1b0d4488; it was edited after it was approved
scaneval: no usable scan from 1 invocation(s): reporting-main.blinded__semgrep-local-rules__r1
exit=1
```

Report standard and blinded results separately: the schedule pairs vulnerable and fixed inputs only
within one profile. A blinded result says the listed cues were absent from the scanned text, not
that the scanner could not recognize the repository.

### A native PR input

A PR input reviews one change: a base and a head snapshot of one repository, declared in the pack as
a change set, run once per system and repetition, against a history of exactly two commits. A full
scan of the head is a different measurement and never stands in for it. The example is one pull
request against the reporting service: `app/report.py` now concatenates a customer id into a SQL
string, `app/export.py` is added, `app/legacy.py` is deleted, `lib/fmt.py` is renamed to
`lib/format.py`, and `scripts/export.sh` becomes executable.

Pin both commits, import the finding on the head, and check both exports. `corpus validate`
records each export's tree hash in the pack, and the run's schedule can freeze a PR input's plan
only when both snapshots declare theirs; a run checks both exports again itself, and a snapshot no
case references says so:

```sh
BASE=$(git -C "$BYOC/source" rev-parse HEAD~1); HEAD=$(git -C "$BYOC/source" rev-parse HEAD)

$SB corpus add-snapshot "$BYOC/pr-pack.json" --snapshot-id reporting-base --url "$BYOC/source" \
  --name acme/reporting-service --commit "$BASE" --language python --workload conventional_application \
  --component-role application --reference "the commit the pull request branched from" --role ordinary
$SB corpus add-snapshot "$BYOC/pr-pack.json" --snapshot-id reporting-head --url "$BYOC/source" \
  --name acme/reporting-service --commit "$HEAD" --language python --workload conventional_application \
  --component-role application --reference "the head of the pull request"
$SB corpus import "$BYOC/pr-pack.json" --case-id report-sqli --snapshot-id reporting-head \
  --represents "This case tests SQL built by string concatenation under a default deployment, and adds a Python query sink." \
  --workload conventional_application --component-role application --finding "$BYOC/finding.json"
```

Controls are written into the pack by hand (section 3), and a hand edit of a record a plan reads must
be followed by rebuilding the pack's anchor, which no command does: a pack whose anchor no longer
verifies does not load. Here two capability-safe controls were added to the case, one on the
neighbouring query and one on a token comparison in a file the pull request never touched:

```sh
python - <<'PY'
import json, pathlib
from scaneval.contracts import pack_anchor_digest
path = pathlib.Path("/private/tmp/byoc/pr-pack.json")
pack = json.loads(path.read_text())
pack["cases"][0]["controls"] = controls   # your control records: C-count-parameterized (app/report.py:12), C-token-compare (app/auth.py:5)
pack["anchor_sha256"] = pack_anchor_digest(pack)
path.write_text(json.dumps(pack, indent=2) + "\n")
PY
```

```
$ $SB corpus validate "$BYOC/pr-pack.json" --snapshot-id reporting-base --cache-root "$BYOC/cache" --trial-root "$BYOC/trials"
Exported reporting-base to /private/tmp/byoc/trials/reporting-base (sha256:7dae9be43bbe78748c42a532f5c89a49bbeb196e931b3fce0f4531a0c38fafa2)
No case references snapshot reporting-base; nothing was checked.
exit=0
$ $SB corpus validate "$BYOC/pr-pack.json" --snapshot-id reporting-head --cache-root "$BYOC/cache" --trial-root "$BYOC/trials"
Exported reporting-head to /private/tmp/byoc/trials/reporting-head (sha256:507c6e68fc74d42e97378b8ee220d4525701adeac45a91947d1e4453a3356f36)
report-sqli: pass (mechanically_checked, level L1)
exit=0
```

Declare the change set, and state which items the review scores. `--boundary` says what kind of
change it is (`introducing`, `repair`, or `ordinary`) and `--review-scope` the scope declared before
any run (`changed_files` or `change_affected_flow`); both are claims a curator makes. The first
change set upgrades the pack from 2.0 to 2.1:

```
$ $SB corpus add-change-set "$BYOC/pr-pack.json" --change-set-id pr-4821 \
      --base-snapshot-id reporting-base --head-snapshot-id reporting-head \
      --boundary introducing --review-scope changed_files \
      --description "The pull request that builds the report query from the customer id." \
      --reference "acme/reporting-service#4821"
{"base_snapshot_id":"reporting-base","boundary":"introducing","change_set_id":"pr-4821",
 "description":"The pull request that builds the report query from the customer id.",
 "head_snapshot_id":"reporting-head","reference":"acme/reporting-service#4821",
 "review_scope":"changed_files"}
exit=0

$ $SB corpus pr-scope "$BYOC/pr-pack.json" --case-id report-sqli --change-set-id pr-4821 \
      --relation introduced --code-scope changed --note "the concatenation is on a changed line"
{"change_set_id":"pr-4821","code_scope":"changed","note":"the concatenation is on a changed line","relation":"introduced"}
exit=0

$ $SB corpus pr-scope "$BYOC/pr-pack.json" --case-id report-sqli --control-id C-count-parameterized \
      --change-set-id pr-4821 --relation affected --code-scope context \
      --note "the neighbouring query the change sits beside"
{"change_set_id":"pr-4821","code_scope":"context","note":"the neighbouring query the change sits beside","relation":"affected"}
exit=0
```

An item with no entry for a change set is outside that review. The token control names none, so it
is not in the plan, earns nothing there, and a quiet scan earns it no credit; an eligible control
still needs a completed run and a resolved assessment like any other. A target is `introduced` or
`affected`, never `repaired`, and every item named must be on the change set's head snapshot, since
a PR review reads the head. Eligibility is a label: if the case had already been approved, the
approval would no longer cover it, `pr-scope` would say so on stderr, and nothing would carry the
approval across. `corpus canonical` is the same kind of write for a canonical root cause or property.

A PR input is configured by its change set and needs a 2.1 configuration. The first system below
runs the own harness's pr mode with its mock runner, which calls no model; the second is Semgrep,
which does not declare `pr` in this build:

```json
{
  "schema_version": "2.1",
  "run_id": "acme-pr-4821",
  "pack": "pr-pack.json",
  "cache_root": "cache",
  "inputs": [{"mode": "pr", "change_set_id": "pr-4821"}],
  "systems": [
    {"system_id": "harness-mock", "adapter": "llm-harness",
     "config": {"harness": "securevibes-agent", "root": "~/src/securevibes-agent", "model": "test/mock-llm",
                "runner": "mock", "qmd_profile": "lite", "llm_max_files": 5, "llm_timeout_ms": 20000}},
    {"system_id": "semgrep-local-rules", "adapter": "semgrep",
     "config": {"ruleset": {"url": "/private/tmp/byoc/rules", "commit": "<rules commit>", "paths": ["python"]}}}
  ],
  "repetitions": 1, "timeout_seconds": 600, "trace_mode": "metadata", "network_policy": "none"
}
```

```
$ $SB run "$BYOC/run-pr.json" --output "$BYOC/runs/pr-4821" --workspace-root "$BYOC/workspaces"
pr-4821__harness-mock__r1 status=success claims=0 plan=draft review=draft
pr-4821__semgrep-local-rules__r1 status=unsupported claims=0 plan=draft review=draft
Manifest: /private/tmp/byoc/runs/pr-4821/run-manifest.json
Schedule: /private/tmp/byoc/runs/pr-4821/evaluator/schedule.json
exit=0
```

There is one invocation per change set, system, and repetition, named `<change set id>__<system>__r<n>`.
The input's directory holds the head in `source` and the base in `base/source`, beside the
preparation record. The manifest row is about the head snapshot and names the change set, and its
input hash is the identity of the change, not of the head alone:

```
$ jq -c '.inputs[] | {input_id, mode, snapshot_id, change_set_id, tree_hash, input_hash}' "$BYOC/runs/pr-4821/run-manifest.json"
{"input_id":"pr-4821","mode":"pr","snapshot_id":"reporting-head","change_set_id":"pr-4821",
 "tree_hash":"sha256:507c6e68fc74d42e97378b8ee220d4525701adeac45a91947d1e4453a3356f36",
 "input_hash":"sha256:79db80dde3fb3c4970698f1ada4c567d3b76c90962cc7b12de34b519593c4815"}
```

Because both snapshots declared their tree hashes before the run, the schedule froze the eligibility
first. Its input row carries the change set as declared and the plan the pack gave it, each item with
its scope, and the item the change set does not name is said to be outside it:

```
$ jq -c '.inputs[0].plan | {state, targets: [.targets[] | {target_id, pr_scope}], controls: [.controls[] | {control_id, pr_scope}], notes}' "$BYOC/runs/pr-4821/evaluator/schedule.json"
{"state":"frozen","targets":[{"target_id":"T-report-sqli","pr_scope":{"code_scope":"changed","relation":"introduced"}}],
 "controls":[{"control_id":"C-count-parameterized","pr_scope":{"code_scope":"context","relation":"affected"}}],
 "notes":["outside change set pr-4821, so not planned and earning nothing in this review: C-token-compare"]}
```

The scanner is handed the head as its working tree and a history of two neutral commits, and its
request names those commits and nothing else about the change. The change itself, kind by kind, is
in the execution record, evaluator-side and with no path in it:

```
$ jq -c '.input' "$BYOC/runs/pr-4821/invocations/pr-4821__harness-mock__r1/request.json"
{"languages":["python"],"mode":"pr","pr":{"base":"ca358dadc0c9138daa2797a713d466f3c6a9d7bb","head":"2319dd24544596bc40a322291e2d593659065ee6"},
 "profile":"standard","root":".","tree_hash":"sha256:507c6e68fc74d42e97378b8ee220d4525701adeac45a91947d1e4453a3356f36"}

$ jq -c '.provenance.pr | {change_set_id, boundary, review_scope, diff_sha256, changes, prepared_state}' "$BYOC/runs/pr-4821/invocations/pr-4821__harness-mock__r1/execution.json"
{"change_set_id":"pr-4821","boundary":"introducing","review_scope":"changed_files",
 "diff_sha256":"sha256:59a6136b2ca5dced34b30540e981cd11285ec618eb56b9ffd1c3d3a38b48bbd7",
 "changes":{"added":["app/export.py"],"deleted":["app/legacy.py"],"mode_changed":["scripts/export.sh"],
            "modified":["app/report.py"],"renamed":[["lib/fmt.py","lib/format.py"]]},
 "prepared_state":"fresh"}
```

Inside the scanner's workspace `git diff --name-status` between those two commits lists the same
files: `A app/export.py`, `D app/legacy.py`, `M app/report.py`, `R100 lib/fmt.py lib/format.py`, and
`M scripts/export.sh`. A rename is recorded only when the bytes are identical, and only when exactly
one deleted path and one added path hold them. The commit ids are computed once in preparation and
every workspace must reproduce them, or the invocation is refused before the scanner runs. Neither
commit is a commit of your repository: the history holds the two trees, the identity
`ScanEval <scaneval@localhost>`, and one fixed date.

The plan the invocation is scored against carries the eligible items only, each with its scope, the
pack's `pr` budgets, and the boundary; a claim's location is a location in the head:

```
$ jq -c '{scope, review_budgets, controls: [.controls[].control_id], pr: (.provenance.pr | {change_set_id, boundary, location_basis})}' "$BYOC/runs/pr-4821/invocations/pr-4821__harness-mock__r1/evaluator/plan.json"
{"scope":"draft","review_budgets":[5,10,20],"controls":["C-count-parameterized"],
 "pr":{"change_set_id":"pr-4821","boundary":"introducing","location_basis":"pr_head"}}
```

Semgrep is recorded `unsupported`, not run and not scanned as a whole tree in its place. Its
invocation stays in every denominator, and completes no control, so a quiet result earns nothing:

```
$ jq -c '{status, error}' "$BYOC/runs/pr-4821/invocations/pr-4821__semgrep-local-rules__r1/result.json"
{"status":"unsupported","error":{"code":"unsupported_mode","message":"semgrep does not declare support for pr scans; it carries out: full"}}

$ jq -c '.metrics.controls.capability_safe | {assigned, completed, resolved}' "$BYOC/runs/pr-4821/invocations/pr-4821__semgrep-local-rules__r1/evaluation.json"
{"assigned":1,"completed":0,"resolved":0}
```

A PR input fails on its own, like any other input: a change with nothing in it (`no change to
review`), a declared tree hash the export contradicts, a history git reads differently from the
export, or a blinding map that does not fit either snapshot is recorded against that input, its
assignments are skipped invocations, and the other inputs still run. A `metadata_blinded` PR input
is transformed with one map for both snapshots, whose variants must cover both, and the originals
stay evaluator-side; the plan names the map and the labels still refer to the original head.

This is a native review of a change, not an evaluation of a hidden-intent change and not a vulnerable
and fixed pair: no pair of PR inputs is defined, so a PR result carries no pair correctness.

## 7. The human review loop on a bundle

A bundle is a directory holding `result.json` and an `evaluator/` directory. The loop is four
commands and a text editor.

**`review init BUNDLE --pack PACK`** routes saved claims to planned targets as unresolved
candidates and writes `evaluator/decisions.json` and `evaluator/review-record.json`. Routing is by
accepted location path only. It does not read claim prose, compare line ranges, weigh severities,
or establish a root cause.

```
$ $SB review init "$BYOC/manual-bundle" --pack "$BYOC/runs/2026-09-20/evaluator/pack.json"
Routed 1 candidate claim matches and 0 control assessments; every decision stays unresolved.
```

The runner already writes `plan.json`, `decisions.json`, and `review-record.json` into every
invocation bundle it produces, so `review init` is for a bundle that has a result and a plan but no
decisions yet. The pack it is given must be the one the plan was built from. For a bundle the
runner produced, that is the run's frozen copy at `<run>/evaluator/pack.json`, not the pack file on
disk, whose hash changed when the run re-ran the mechanical checks.

**Edit `evaluator/decisions.json` by hand.** A claim match decision becomes `accepted` or
`rejected`; a control assessment becomes `false_allegation` (with at least one `claim_ids` entry)
or `quiet` (with none). Those four values are the human conclusions; `unresolved` is the only
value the tool writes.

```json
[{"claim_id":"c1","decision":"accepted",
  "reason":"Reviewed: the claim names the shell call that builds the command from the account parameter.",
  "target_id":"T-acme-report-shell"}]
```

**`review record BUNDLE [--note ...]`** re-drafts the review record for the edited decisions. The
new record is a draft, so re-drafting never carries an approval forward. Reviews an existing
record holds are copied in as history, each still naming the decisions hash it was recorded
against.

```
Review record state: draft (0 recorded reviews)
decisions_sha256: sha256:90edaf58856901126da54ca09cc51f365b291242a2e0d6895a6d50a418c06b79
plan_sha256: sha256:0a5253c906d0b0c0f039b5381b88e124b68d2d2101e8755297f29bb9f4be3239
```

**`review approve BUNDLE --reviewer NAME --note TEXT`** appends one approval and replaces only the
record file.

```
Review record state: human_approved (1 recorded reviews)
```

**`review status BUNDLE`** prints `missing`, `stale`, `draft`, or `human_approved`. It reads and
writes nothing.

`review approve` does not require that any decision was resolved. Approving an untouched machine
draft succeeds and records a human approval of a set of decisions that are all `unresolved`, which
still earns no detection credit. The record states who approved what; the decisions state what was
concluded.

After approval, `replay` recomputes the scores offline from the saved documents:

```json
{"scope":"reviewed","status":"success",
 "metrics":{"targets_assigned":1,"targets_detected":1,"known_target_recall":1.0,"pending_matching_count":0},
 "warnings":["Random-order expectation is not native prioritization or a promotion metric."]}
```

### What each binding refuses

| Binding | Refusal |
|---|---|
| routing pack against `plan.provenance.pack_sha256` | `the routing pack is not the pack the plan was built from` |
| decisions against the plan's `input_hash` | `the decisions and the plan bind to different input hashes` |
| decisions against `result.json` bytes and `run_id` | `the decisions were filed against a different result than <path>` (on `review record` and `review approve`), and `Review result_sha256 does not match the saved result` (on `score` and `replay`) |
| record against the decisions on disk | `the decisions changed after this record was made; draft a new record before approving`, and `review status` reports `stale` |
| record against the decisions and plan, on re-draft | `the existing review record already binds to these decisions and plan`, so an approval already on disk is never overwritten |
| existing decisions file | `refusing to overwrite <path>/evaluator/decisions.json` |
| bundle path spelled through a symlink | `refusing to use <path>: it does not resolve to itself ...; name the bundle by its real path` |

The last one matters on macOS, where `/tmp` is a symlink to `/private/tmp`: the writing review
commands refuse the `/tmp` spelling, while the read-only commands (`review status`, `replay`,
`report`) resolve the path and report on the bundle it reaches.

These are document-to-document hash bindings. Matching hashes say nothing about the input tree,
the scanner run, the pack's evidence, or whether a human read anything. A `human_approved` record
is the record's own assertion. The scorer never reads the review record, so an approval cannot
raise a draft plan into reviewed evidence.

## 8. Privacy and boundaries, as limits

These are limits of the current implementation, not guarantees about your environment.

| Area | What the code does | What it does not do |
|---|---|---|
| Storage | Every pack, plan, decision, run directory, raw output, and trace is written to a local path you name. | Nothing uploads, syncs, or publishes. Enforcing "organization-controlled" is a property of the filesystem you point it at, not of this tool. |
| Network during preparation | `git fetch` of the snapshot URL and of an adapter's pinned ruleset URL, with `GIT_TERMINAL_PROMPT=0`. | No advisory lookup, no registry ruleset download, no maintainer contact. |
| Remote inference | The run configuration declares `network_policy` per run and per system, and the execution record states `{"declared": "none", "enforced": false, "note": "Policy is recorded, not enforced by this runner; enforce it in the execution environment."}`. | The runner does not block a single packet. A model-backed adapter sends source to its provider whenever it is configured to. An approved data-egress and retention policy is an organizational decision the tool only records as a string. |
| Credentials | `--url`, `--historical-url`, and `--repo` refuse a URL whose authority carries userinfo, except the bare `git` user of an ssh clone URL. The run configuration has no credential field. Scanner subprocesses receive only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `TERM`, `USER`, `SHELL` unless the adapter adds more. | The check reads the URL authority only: a token in a path, a query, or an scp-style `git@host:path` address is not detected. The `llm-harness` adapter adds `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and `XDG_CONFIG_HOME` to that passthrough, and `deepsec` adds `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`, so provider keys in your environment do reach those scanner processes; neither is recorded. `NODE_OPTIONS` is deliberately passed by neither, because node executes what it names and a `--require` in your environment would run code inside the scanner while the record showed only a variable name. |
| Traces | `trace_mode` is `off`, `metadata`, or `content`. Metadata mode omits content. Content mode stores a cloned, redacted copy of metadata and content, including the outgoing model request, in the bundle's `trace/` directory. | Content-mode traces therefore contain the source that was sent to the model. Treat a content-mode bundle as source material, with the same handling rules. The default redactor replaces common credential-looking keys; it is not a secret scanner. |
| Directory separation | Evaluator files live in `evaluator/` and in the pack; the scanner receives a private workspace copy of one export. The trial-path check refuses writing evaluator material inside an exported tree, and the runner refuses a workspace inside evaluator storage. | These compare resolved paths. They follow no bind mount or hard link, and they are not a sandbox. Directory separation documents the evaluator boundary; it does not enforce it. |
| Exported trees | The export carries tracked regular files only, strips `.git`, `.securevibes`, `.scaneval`, and `.repos`, records skipped submodules and symlinks, and records retained instruction files such as `CLAUDE.md` or `AGENTS.md` as identity cues. A blinded export also keeps the original export evaluator-side and records every edit and every remaining cue. | It is not a sandbox, and instruction files stay in the tree under both profiles. Blinding never renames a package, import, identifier, or path, so a blinded tree is not anonymous. |
| Pack edits | A pack is replaced atomically through a temporary file and a rename, keeping the previous permission bits. | No previous version is kept on disk. Keep the pack under version control if you need history or a correction trail. |

## 9. What is not implemented yet

- **No Jev intake assistance.** There is no Jev code in `src/`. No command suggests
  classifications, evidence gaps, duplicates, or fix candidates. Drafting and review are manual.
- **Native PR review is fresh-state only.** `llm-harness`, `semgrep`, and `deepsec` each review a
  PR input with their own diff workflow; an adapter without a PR mode is recorded `unsupported`, and a
  full scan of the head never stands in for it. Every PR run starts from a fresh state: a
  prepared-state run is not implemented, and no vulnerable/fixed pair of PR inputs is defined.
- **No cross-pack weighting.** `scaneval aggregate` combines the inputs, systems, and repetitions
  of saved runs of one pack into weighted corpus metrics ([aggregation](AGGREGATION.md)). It
  refuses runs of different packs. Private and public results stay separate because aggregation
  reads one frozen pack at a time, not because a cross-pack weighting exists.
- **No promotion gate.** No command promotes a pack from `draft` to `reviewed` or `released`, and
  no command sets a case's `split` to `development` or `evaluation`; imports leave it `unassigned`.
  Freezing membership and promoting a version are hand edits to the pack file, reviewed in your own
  repository. `scaneval gate` judges a saved comparison against a policy and promotes nothing, a
  pack version included ([gate](GATE.md)).
- **Metadata blinding is partial, and nothing finds cues for you.** A map edits the documentation
  and display metadata a reviewer listed and nothing else. Nothing discovers identity cues, reads
  source, or decides whether a field is read at runtime, and the run's leak check matches only the
  spellings the map declares. A blinded input is never replaced by a `standard` export: a map that
  is not approved or does not fit fails that input instead.
- **No case-authoring skill yet.** The design pairs this guide with a case-authoring `SKILL.md`.
  The CLI operations it would drive are the ones documented here.
- **Admission is a record, not a gate,** and `extended_regression` is planned like any other
  disposition. Both are covered in section 5.

## Verification note

Every command and every output in this guide was produced with `scaneval 2.0.0a1` on 2026-09-20,
against a throwaway pack under `/private/tmp/byoc` whose snapshot source and whose Semgrep ruleset
were both local `git init` repositories. Nothing in the transcript reached the network. The
schedule, preparation-failure, and blinding transcripts in section 6 were produced on 2026-09-29
the same way, against a pack of the same shape in another temporary directory, with paths shown under
`/private/tmp/byoc`; the native PR transcript there was produced on 2026-09-30 against a local
repository of one pull request, with the own harness's mock runner (no model call) and a local Semgrep
ruleset, and the hand-added controls it describes; the `Schedule:` line in the first run transcript is the line `run` has printed
since then. Re-check these behaviors against the current checkout rather than treating this guide
as a guarantee.
