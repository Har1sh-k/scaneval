# Bring your own corpus

This guide documents the organization-owned case pack path as the code implements it today, in
package version `2.0.0a1`. It is the documentation deliverable named in
[design decisions section 9](DESIGN_DECISIONS.md#9-bring-your-own-test-cases) and it follows the
bring-your-own-case path in [the handoff](CLAUDE_HANDOFF.md).

Every command below was run against a throwaway pack under `/private/tmp/byoc` whose snapshot
source was a local `git init` repository, so nothing in this guide needs the network. Where the
design asks for something the code does not do yet, the gap is stated in the section it belongs
to. Section 9 collects the gaps.

Two conventions used throughout:

```sh
SB=/Users/hk/Documents/GitHub/sast-bench/.venv/bin/sastbench   # or `sastbench` on PATH
BYOC=/private/tmp/byoc                                          # the organization's working directory
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
| Same contract | `src/sastbench/schemas/case-pack.schema.json` is the one contract for public and organization-owned packs. There is no private variant of the schema. |
| Same evaluation | `sastbench plan`, `sastbench run`, `sastbench review`, `sastbench score`, `sastbench replay`, and `sastbench report` do not ask whether a pack is public. Adapters, the observer trace mode, and `sastbench.scoring.score` are shared. |
| Organization controlled | Every file the CLI writes is a local file you name. The only network use is `git fetch` of the snapshot URL you declared and of an adapter's pinned ruleset URL, plus whatever a model-backed adapter does with its provider. |

Nothing in a pack is ever copied into a scanner workspace. The scanner receives a private
workspace copy of one exported source tree and a scan request that carries no labels:

```json
{"input":{"languages":["python"],"mode":"full","profile":"standard","root":".",
          "tree_hash":"sha256:2ae31545c1e6cde1b334fb37c174c5d1071533ead71f95a755a6c86a8ba8c184"},
 "limits":{"timeout_seconds":600},"run_id":"acme-internal-pilot-2026-09-20",
 "schema_version":"2.0","system":{"id":"semgrep-local-rules"},"trace_mode":"off"}
```

Three checks in the code keep pack material out of that tree. `sastbench.cases` never writes
outside the pack. Every command that names a path it may write refuses a path inside a
materialized trial directory, which is recognized by a `provenance.json` file beside a `source`
directory. The runner refuses a scanner workspace that resolves inside the run output, the source
cache, or an exported input.

```
$ $SB plan --pack "$BYOC/pack.json" --snapshot-id reporting-main --tree-hash "$TREE" \
      --output "$BYOC/trials/reporting-main/source/plan.json"
sastbench: refusing to write /private/tmp/byoc/trials/reporting-main/source/plan.json inside the
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

The handoff states the path as: supplied artifact, then candidate and evidence draft, then human
approval, then versioned pack, then evaluation. The commands map onto it directly.

| Step | Command | What it records |
|---|---|---|
| Supplied artifact | `corpus import` | One draft case, one evidence record per artifact, disposition `needs_evidence`, review state `draft`. |
| Candidate and evidence draft | `corpus validate --snapshot-id` | An export of the pinned snapshot plus one L1 check set per case, recorded in the pack. |
| Human approval | `corpus disposition`, `corpus approve`, `corpus admit` | A screening decision, one named review per case, one named admission decision. |
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

Then one import per supplied artifact. Section 3 covers the four forms; this is the legacy record:

```sh
$SB corpus import "$BYOC/pack.json" \
  --case-id acme-report-shell \
  --snapshot-id reporting-main \
  --represents "This case tests shell command construction from an HTTP query parameter under the assumption that the reporting endpoint is reachable by unauthenticated users, and adds the organization's only process-execution mechanism in a Flask handler." \
  --workload conventional_application --component-role application \
  --legacy-case "$BYOC/legacy-case.json"
```

```
Imported draft case acme-report-shell: 2 evidence records, disposition needs_evidence, review state draft, level None
```

`corpus validate` with no `--snapshot-id` schema-checks the pack and prints a summary:

```sh
$SB corpus validate "$BYOC/pack.json"
```

```json
{"cases":4,"dispositions":{"exclude":0,"extended_regression":0,"needs_evidence":4,"validate":0},
 "namespace":"acme.security","pack_id":"internal-pilot",
 "review_states":{"draft":4,"human_approved":0,"mechanically_checked":0},
 "sha256":"sha256:3ff236502817723166463e74202badbf5276b280c518cc890edc0605a0e368c8",
 "snapshots":1,"status":"draft","version":"0.1.0-draft"}
```

With `--snapshot-id` it fetches the commit into an immutable cache, exports it into a new trial
directory, and runs the L1 checks:

```sh
$SB corpus validate "$BYOC/pack.json" \
  --snapshot-id reporting-main \
  --cache-root "$BYOC/.repos" \
  --trial-root "$BYOC/trials"
```

```
sastbench: mechanical checks failed for 2 case(s): acme-report-fix, acme-report-incident; the results are recorded in the pack
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
sastbench: pack status is released, not draft; changing it needs --new-version <version>, which opens a new draft version of this pack
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

## 3. The four intake forms

`corpus import` takes exactly one artifact flag. The four are mutually exclusive and one is
required:

```
sastbench corpus import: error: one of the arguments --legacy-case --fix-commit --finding --document is required
```

| Flag | Evidence `origin` | Evidence `kind` | `reference` | Accepted locations |
|---|---|---|---|---|
| `--legacy-case FILE` | `legacy_case_record` for the record itself; a named GHSA or CVE is `public_advisory_and_maintainer_fix`, and a fix commit takes that origin only when an advisory is named too, otherwise `fix_without_advisory` | `other`, plus `fix_commit`, `ghsa_advisory`, `cve_record` as present | the file path, and `<repo>@<sha>` for the fix commit | each legacy region becomes a candidate location with role `other` |
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

Three details that matter for internal material:

- `--alias` takes the identifiers your organization already uses. An internal ticket or review
  id passes the L1 check `aliases_well_formed` unchanged, because a CVE is neither required nor
  sufficient for a case. An identifier that begins with `CVE` or `GHSA` is held to the public
  shape, so a typo in a published id is caught rather than carried into the pack:

  ```
  acme-alias-probe: fail (draft, level None); failed: CVE-2026-1 is not a well formed CVE or GHSA identifier
  ```

- The legacy migration records a fix commit as `public_advisory_and_maintainer_fix` only when the
  legacy record also names a CVE or a GHSA. A record with a fix commit and no advisory, the
  ordinary shape of an internal fix, is recorded as `fix_without_advisory` with a note saying no
  public disclosure is claimed.

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
sastbench: approval requires an explicit reviewer name; the tool never supplies one
exit=2

$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-fix --reviewer "R. Mehta" --role independent_reviewer --level L3 --note "x"
sastbench: case acme-report-fix has not passed mechanical checks; run corpus validate first
exit=2

$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-shell --reviewer "P. Adeyemi" --role curator --level L3 --note "x"
sastbench: L3/L4 labels require an independent_reviewer decision
exit=2

$ $SB corpus approve "$BYOC/pack.json" --case-id acme-report-allegation --reviewer "R. Mehta" --role independent_reviewer --level L3 --note "x"
sastbench: L3/L4 require disposition validate
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
sastbench: case acme-report-shell: L3 requires disposition validate, not needs_evidence
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

`sastbench run CONFIG --output DIR` executes one frozen configuration. The contract is
`src/sastbench/schemas/run-config.schema.json`.

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | `"2.0"`. |
| `run_id` | yes | Matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`. |
| `pack` | yes | Path to the case pack, relative to the configuration file. |
| `cache_root` | no | Immutable source cache, relative to the configuration file. Default `.repos`. |
| `inputs[].snapshot_id` | yes | A snapshot the pack declares. Refused before anything is written otherwise. |
| `inputs[].profile` | no | `standard` (default) or `metadata_blinded`. |
| `systems[].system_id` | yes | Matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`. |
| `systems[].adapter` | yes | `semgrep` or `llm-harness` in this build. |
| `systems[].config` | yes | Adapter configuration. For `semgrep` this pins a rules repository by url, commit, and paths. |
| `systems[].model_id`, `model_revision` | no | Recorded in the scan request and the execution record. |
| `systems[].network_policy` | no | Overrides the run-level policy for this system. |
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
```

`--output` must not exist. `--workspace-root` must exist and must resolve outside the run output,
the source cache, and every exported input; a workspace root that does not exist fails the run.
`--only-input` and `--only-system` narrow the run and are refused when they name something the
configuration does not contain. What was narrowed away is recorded in the manifest's `selection`.

`run` exits `1`, not `0`, when any invocation ended in `error`, `timeout`, or `skipped`, or when
the manifest status is not `completed`. The bundles it did produce are still there.

### The run directory

```
runs/2026-09-20/
  run-config.json                      canonical copy of the configuration that was executed
  run-manifest.json                    what ran, what was skipped, where every artifact landed
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

`trace/` appears in the bundle as well when `trace_mode` is not `off`. The invocation id is
`<input>__<system>__r<repetition>`; a configuration whose ids would collide is refused before the
output directory is created.

The run never edits the source pack on disk. Its mechanical check results land only in the frozen
copy at `evaluator/pack.json`, which is written once, after every input is prepared and before the
first invocation. That frozen copy is the pack a later `review init` must be given, because the
re-run checks give the frozen copy a different hash from the pack file on disk.

Once the output directory exists, every later failure is recorded there. A run refused for an
unimplemented input profile still leaves a manifest:

```
$ $SB run "$BYOC/run-blinded.json" --output "$BYOC/runs/blinded" --workspace-root "$BYOC/workspaces"
sastbench: metadata blinding unavailable: no reviewed replacement map was supplied
exit=2

$ jq -c '{status, failure}' "$BYOC/runs/blinded/run-manifest.json"
{"status":"failed","failure":{"message":"metadata blinding unavailable: no reviewed replacement map was supplied","type":"MaterializationError"}}
```

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

`sastbench plan` builds the same plan outside a run, which is useful for seeing what would be
planned before spending a scan:

```sh
$SB plan --pack "$BYOC/pack.json" --snapshot-id reporting-main --tree-hash "$TREE" \
  --output "$BYOC/plan-reviewed.json" --mode full
```

`--mode pr` changes exactly one thing today: the plan carries the pack's `pr` review budgets
instead of its `full` budgets, and records `"mode": "pr"` in its provenance. See section 9.

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
| Credentials | `--url`, `--historical-url`, and `--repo` refuse a URL whose authority carries userinfo, except the bare `git` user of an ssh clone URL. The run configuration has no credential field. Scanner subprocesses receive only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `TERM`, `USER`, `SHELL` unless the adapter adds more. | The check reads the URL authority only: a token in a path, a query, or an scp-style `git@host:path` address is not detected. The `llm-harness` adapter adds `NODE_OPTIONS`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and `XDG_CONFIG_HOME` to that passthrough, so provider keys in your environment do reach that harness process. |
| Traces | `trace_mode` is `off`, `metadata`, or `content`. Metadata mode omits content. Content mode stores a cloned, redacted copy of metadata and content, including the outgoing model request, in the bundle's `trace/` directory. | Content-mode traces therefore contain the source that was sent to the model. Treat a content-mode bundle as source material, with the same handling rules. The default redactor replaces common credential-looking keys; it is not a secret scanner. |
| Directory separation | Evaluator files live in `evaluator/` and in the pack; the scanner receives a private workspace copy of one export. The trial-path check refuses writing evaluator material inside an exported tree, and the runner refuses a workspace inside evaluator storage. | These compare resolved paths. They follow no bind mount or hard link, and they are not a sandbox. Directory separation documents the evaluator boundary; it does not enforce it. |
| Exported trees | The export carries tracked regular files only, strips `.git`, `.securevibes`, `.sastbench`, and `.repos`, records skipped submodules and symlinks, and records retained instruction files such as `CLAUDE.md` or `AGENTS.md` as identity cues. | It is not a sandbox, and instruction files stay in the tree under the `standard` profile. |
| Pack edits | A pack is replaced atomically through a temporary file and a rename, keeping the previous permission bits. | No previous version is kept on disk. Keep the pack under version control if you need history or a correction trail. |

## 9. What is not implemented yet

- **No Jev intake assistance.** There is no Jev code in `src/`. No command suggests
  classifications, evidence gaps, duplicates, or fix candidates. Drafting and review are manual.
- **No native PR mode through this path.** `plan --mode pr` only selects the pack's `pr` review
  budgets and records `"mode": "pr"`. The runner always plans in `full` mode, and no run
  configuration field asks an adapter for a diff review, so no PR invocation can be produced here.
- **No corpus aggregation or cross-pack weighting.** The runner produces single-invocation numbers
  only. Nothing combines inputs, systems, repetitions, or packs, and nothing weights families or
  computes repeated-run uncertainty. Private and public results are separate because nothing
  merges them, not because a weighting exists.
- **No promotion gate.** No command promotes a pack from `draft` to `reviewed` or `released`, and
  no command sets a case's `split` to `development` or `evaluation`; imports leave it `unassigned`.
  Freezing membership and promoting a version are hand edits to the pack file, reviewed in your own
  repository. The report states the same limit: "Single-input metrics only. Corpus weighting,
  precision estimates, promotion gates and a trace viewer are not implemented in this build."
- **Metadata blinding is refused, not approximated.** `profile: "metadata_blinded"` fails with
  `metadata blinding unavailable: no reviewed replacement map was supplied`. There is no CLI flag
  that supplies a replacement map; the library call that accepts one refuses it as well, with
  `metadata blinding is not implemented in this build; do not substitute standard`. The run records
  the failure instead of silently scanning a `standard` export.
- **No case-authoring skill yet.** The design pairs this guide with a case-authoring `SKILL.md`.
  The CLI operations it would drive are the ones documented here.
- **Admission is a record, not a gate,** and `extended_regression` is planned like any other
  disposition. Both are covered in section 5.

## Verification note

Every command and every output in this guide was produced with `sastbench 2.0.0a1` on 2026-09-20,
against a throwaway pack under `/private/tmp/byoc` whose snapshot source and whose Semgrep ruleset
were both local `git init` repositories. Nothing in the transcript reached the network. Re-check
these behaviors against the current checkout rather than treating this guide as a guarantee.
