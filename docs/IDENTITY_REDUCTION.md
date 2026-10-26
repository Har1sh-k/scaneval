# Reviewed identity-reduced exports

`identity_reduced` exports reduce selected repository and answer cues while preserving runtime
code, dependency declarations, package/import names, source paths, licenses, build/CI settings,
and security configuration. They retain an evaluator-side original and a deterministic record of
every transformation, skip, instruction-file disposition, and inspected residual. Recognizable
code and useful project context remain. An available export is not anonymous and cannot establish
that a model had no prior exposure to the code.

A profile name selects an export operation. It does not establish a complete experimental
condition. A legacy reviewed removal map can still export without `identity_policy`; its strict
summary is `unavailable`. An explicit policy must pass strict preparation before any scanner is
called. That export evidence must be combined with separately verified execution controls and a
frozen paired workload to support a condition comparison. The condition matrix and its paired
report are tracked in [issue #64](https://github.com/Har1sh-k/scaneval/issues/64); ordinary
`scaneval compare` compares systems within the same profile and does not pair profiles.

## Prepare and review a strict map

Start with the original export and the removal map in the
[corpus guide](BRING_YOUR_OWN_CORPUS.md#a-metadata-blinded-input). Keep the map outside the source
repository. One map covers all related snapshots of one repository within a profile, with exact
commit, original tree, and file hashes. Preserve its review history when changing it; the changed
content needs a new review.

Add an explicit policy. This example is illustrative: the aliases and advisory references must
come from your validated case pack, including cases that touch a fixed/control snapshot.

```json
"identity_policy": {
  "policy_id": "scaneval.identity-reduced",
  "version": "1",
  "answer_aliases": [
    {"category": "target_alias", "value": "CVE-2025-12345", "forms": ["CVE_2025_12345"]},
    {"category": "advisory_url", "value": "https://example.invalid/advisories/12345", "forms": []}
  ],
  "instruction_paths": ["docs/assistant-guide.md"],
  "identity_tokens": ["Example Project"],
  "forbidden_artifacts": []
}
```

`required_answers(pack, snapshot_ids)` in `scaneval.identity_policy` derives the required aliases
and CVE/GHSA/vendor advisory references. `snapshot_requirements(pack, snapshot_id)` also returns
the accepted target/control paths used by export and saved-manifest verification. A policy must
declare every required value under its derived category, even if that value does not occur in the
export. An explicitly empty `answer_aliases` list is valid only when there are no required answers.
Declare additional answer spellings and normalized forms after reviewing the actual files; the
tool does not invent every possible spelling. A non-URL advisory reference uses `answer_alias`.

Known instruction names include `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `GEMINI.md`, Cursor,
Windsurf, and Cline rule files, and Copilot instruction documents. Textual instruction documents
under supported assistant directories are inventoried, including nested packages. Use
`instruction_paths` for reviewed equivalents. A declaration adds an inspection requirement; it
does not authorize deleting executable helpers, prompts used at runtime, or assistant
configuration. Each removal still needs its own hash-pinned `removals` entry.

Whole-file removal accepts conventional identity documents and instruction text. Runtime-like
directories, license/attribution files, dependencies, scripts, build/CI/security configuration,
and every accepted target/control path stay protected. A strict map may remove narrowly reviewed
historical advisory prose, such as `SECURITY-ADVISORY.md` or `security/advisories/old.md`, only with
an explicit `role_check` establishing its identity-only role. `SECURITY.md`, executable content,
runtime prompts, and scoring evidence remain protected. This exception is not automatic advisory
deletion.

## Review supported metadata leaves

A package manifest is not generally safe to rewrite. The separate `metadata_edits` allowlist
accepts only these parsed string leaves:

| File | `field_path` |
|---|---|
| `package.json` | `["homepage"]`, `["repository"]`, `["repository", "url"]`, `["bugs"]`, or `["bugs", "url"]` |
| `pyproject.toml` | `["project", "urls", "<literal label>"]` |

Nested package files are supported. Field paths contain literal parsed keys, not JSONPath or
dot-separated selectors. Protected CI, repository machinery, and license directories remain
excluded. Package names, scripts, dependencies, entry points, and arbitrary configuration fields
cannot be selected. A reviewer must establish that the chosen URL is not consumed at runtime.

Add one entry per leaf, with an expectation for every map variant:

```json
"metadata_edits": [
  {
    "edit_id": "package-homepage", "path": "package.json", "field_path": ["homepage"],
    "replacement": "",
    "role_check": "Published project URL only; runtime, build, and security behavior do not read this field.",
    "rationale": "Remove the reviewed public repository identity URL.",
    "expected": [
      {"snapshot_id": "reporting-main", "state": "present",
       "file_sha256": "sha256:<the complete original file digest>",
       "original": "https://example.invalid/upstream/project"}
    ]
  }
]
```

Replace the illustrative digest and original value with the exact exported bytes. Use
`{"snapshot_id": "...", "state": "absent"}` for an absent file. An expected present file with a
stale hash fails preparation. A metadata path cannot also receive ordinary token edits or be
removed. Several distinct leaves in one file must pin the same original hash.

JSON and TOML are fully parsed before and after a unique quoted token replacement. Only the
selected leaves may change, all other bytes remain untouched, and physical line boundaries stay
fixed. TOML may supply `raw_token` inside its per-variant expectation when the exact reviewed
quoted spelling is needed. Duplicate/ambiguous tokens, unsupported forms, and edits overlapping
accepted scoring lines are retained unchanged and recorded in `skipped`; no generic TOML
serialization or source-code rewriting is attempted.

Supported URL leaves without an applied review bound to the final file hash are disclosed as
`unreviewed_identity_metadata` residuals, with their parsed field paths. Unparseable supported
metadata is disclosed as `uninspected_identity_metadata`. This inventory does not modify files
or infer whether their contents are safe to remove. Such repository-identity residuals may
coexist with an available strict export. A declared answer left in any of them still makes the
export unavailable.

## Check, approve, and run

Use the same commands as the basic removal workflow, with the strict policy present:

```sh
scaneval validate blinding-map reporting-identity-reduced-map.json
scaneval blinding check reporting-identity-reduced-map.json --pack pack.json \
  --profile identity_reduced --cache-root .repos
scaneval blinding review reporting-identity-reduced-map.json \
  --reviewer "<named reviewer>" --role independent_reviewer --decision approve \
  --note "Reviewed aliases/forms, instruction disposition, metadata roles, scoring preservation, and residuals."
scaneval run run.json --output results/identity-review
```

Inspect the dry-run transformations, strict availability, and residual counts before approving;
an unapproved check exits 1 even when its transformation checks pass. Configure the identity
input with `"profile": "identity_reduced"` and `"blinding_map": "reporting-identity-reduced-map.json"`.
Keep standard and transformed results in separate profile views. Freeze the same source
population, scanner configuration, budgets, and review policy before interpreting differences.
The full [corpus example](BRING_YOUR_OWN_CORPUS.md#a-metadata-blinded-input) uses local Semgrep
rules on fabricated source and shows the surrounding configuration and review flow.

Scanner-visible run/system/model identifiers, configuration strings, and configured workspace
paths must be neutral. Strict checks cover declared answers/forms, upstream repository names
and URLs, revisions, and declared identity tokens with appropriate boundaries. Short repository
names can be ambiguous with language/runtime settings, so a human must review them. The basic
pseudonym guard also remains active. Never place a redaction dictionary or instructions to name
the answer in source files.

## Read and verify the evidence

Each identity export writes evaluator-side `identity-transform.json` beside its preparation
provenance; a PR base has its own manifest under `base/`. The preparation record's
`identity_reduction` summary names its relative `manifest_path` and binds the policy/version,
configuration and manifest digests, original/transformed tree hashes, counts, residual
categories, and `validation.state/reasons`. The manifest also records original snapshot identity,
map and alias/accepted-path bindings, tool versions, inspected paths, edit/removal hashes,
metadata leaf proofs, instruction dispositions, skipped transformations, and detailed residuals.
Its content is deterministic for identical inputs and tool versions. Portable summary reasons
contain codes and counts rather than aliases or enumerable per-alias hashes.

These are evaluator artifacts. Neither summary, manifest, map, pack, original export, nor review
evidence is scanner input. Strict inspection detects concrete evaluator artifact shapes in
ordinary, wrapped, array, and JSONL content; exclusions may also be pinned by path or file digest
in `forbidden_artifacts`. Ordinary SLSA provenance is not excluded just for its filename.
Structured inspection is bounded to 16 MiB, one million nodes, and depth 128; exceeding the bound
leaves strict validation unavailable. Alias checks include declared forms, Unicode case folding,
and UTF-8/16/32 text encodings. Unsupported filesystem entries also fail closed.

An explicit strict policy that lacks answer coverage or leaves answers, instruction documents,
evaluator artifacts, unsafe configured instructions, unsafe entries, or missing scoring paths
fails input preparation, removes candidate scanner trees, and preserves evaluator-side refusal
evidence. No scanner starts for that input; other inputs can continue. A failed strict export
does not silently become standard. Review a skip containing an answer rather than granting it an
exception or rewriting arbitrary source.

`verify_manifest` recomputes schema/accounting, summary, policy/map/configuration, answer and
accepted-path bindings. With the transformed source present it re-inspects and rebuilds the
derived manifest claims, rejecting inconsistent evidence even when the saved inspection digest
is authentic. Without source it checks the saved controller-authored export evidence and exact
bindings; that is not an independent reinspection. Preserve manifests and the frozen evaluator
context with saved runs for reporting. Export availability alone makes no claim about web
access, original Git visibility, model training data, or the cause of a performance difference.
