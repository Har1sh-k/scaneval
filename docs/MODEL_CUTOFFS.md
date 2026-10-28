# Model cutoffs and recent CVE research

ScanEval records provider-published cutoffs and checks declared public vulnerability
chronology offline. It does not infer what a model actually saw during training,
post-training, retrieval, or a particular evaluation. The registry is a dated
research snapshot, with primary sources fetched October 27–28, 2026 (local and UTC
dates differ), rather than a live catalog or a model availability probe.

The packaged [registry](../src/scaneval/data/model-cutoffs.json) covers 42 researched
Anthropic, OpenAI, Z.ai GLM, and xAI Grok model IDs, plus separate aliases and
unverified routes. Each model retains sources, retrieval date, identity caveats,
published precision, and separate knowledge, reliable-knowledge, and training-data
fields. Null means the reviewed sources did not establish the field.

| Family | Latest established boundary in this snapshot | Meaning and limits |
| --- | --- | --- |
| Claude Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1, Mythos 5.1 | June 2026; conservative upper bound June 30 | Explicit training-data and reliable-knowledge fields; month-end is an inference. [Opus source](https://platform.claude.com/docs/en/models/opus-5-5/overview). |
| OpenAI GPT-5.6 through GPT-6.1 researched variants | June 1, 2026 for GPT-6.1 Terra | Knowledge cutoff only; no separate training-data cutoff established. [Terra source](https://developers.openai.com/api/docs/models/gpt-6.1-terra). |
| Grok 4.7 | May 2026; conservative upper bound May 31 | Knowledge cutoff only; other researched current Grok cutoffs remain unknown. [Model guide](https://docs.x.ai/developers/grok-4-7). |
| GLM, including GLM-5.2 and GLM-5.3 | Unknown | Official guides/cards reviewed did not publish a temporal cutoff. [GLM-5.3 guide](https://docs.z.ai/guides/llm/glm-5.3). |

July 2, 2026 is after the latest *known* UTC safety bound in this snapshot. It is
not a universal training-exclusion threshold: GLM dates remain unknown and OpenAI
and Grok knowledge cutoffs do not establish their last training-data dates. Mythos
Preview has a separately sourced upper bound from its system card; that inferred
bound is preserved without inventing an actual cutoff. Sonnet 4.6's conflicting
provider descriptions remain in the registry; the explicitly labeled, later
training date is used for conservative filtering.

## Offline commands

```sh
scaneval model-cutoffs list
scaneval model-cutoffs check docs/research/recent-cve-chronology.json \
  --model claude-opus-5-5
scaneval model-cutoffs check docs/research/recent-cve-chronology.json \
  --model claude-opus-5-5 --model gpt-6.1-terra --basis documented
```

`training` is the default basis and accepts only documented training-data cutoffs
or provider-supported training bounds. Explicit `--basis documented` prefers
training data, then knowledge, then reliable knowledge and reports the chosen
field for each model. Missing cutoffs and unknown IDs remain unresolved. Known
routing aliases also remain unresolved: record the endpoint and actually served
model, then select its documented ID. This matters for GLM Coding Plan routing,
mutable `-latest` aliases, and third-party model names. A documented ID need not
identify immutable weights; retain the returned identity and execution date in
any later benchmark provenance.

Both commands print JSON and write no files. `check` exits 0 only when at least ten
distinct CVEs are eligible across **every** selected model and satisfy the target
of at least 2 Low, 3 Medium, 3 High, and 2 Critical. Exit 1 means valid but
insufficient or unresolved evidence/coverage; exit 2 means invalid input. Reports
include canonical input hashes, all model outcomes, per-stratum shortages, and
explicit claim limits. `--registry PATH` reads a proposed registry offline.
Neither command executes a model/scanner or changes corpus admission.

## Evidence declaration

Input is JSON with `schema_version: 1`, a declared `severity_authority`, and unique
`candidates`. Each candidate supplies its CVE ID, severity, severity source URL,
and chronology declaration. A draft is valid with no chronology artifacts:

```json
{
  "schema_version": 1,
  "severity_authority": "CNA-primary base severity",
  "candidates": [{
    "cve_id": "CVE-2026-10000",
    "severity": "Low",
    "severity_source_url": "https://example.com/advisory",
    "chronology": {
      "status": "pending",
      "review_note": "Earlier issue, PR, advisory, release, patch and PoC history still needs review.",
      "public_artifacts": []
    }
  }]
}
```

The example CVE above is fabricated. To declare reviewed chronology, set `status`
to `reviewed` only after inspecting earlier public history, explain that work in
`review_note`, and supply one or more public artifacts with `kind`, `source_url`,
`date`, `precision` (`day` or `month`), and `date_basis: public_availability`.
Kinds are `advisory`, `issue`, `pull_request`, `release`, `public_commit`, and
`proof_of_concept`. Retain every relevant earlier artifact; the helper uses the
minimum date lower bound. A month is conservatively expanded to its first day for
public evidence and its last day for a cutoff. Provider cutoff time zones are not
established, so the helper preserves that original date/precision and reports a
separate `utc_safety_upper_bound` one calendar day later, explicitly labeled an
inference. This also applies to the Mythos Preview temporal bound; it does not
claim that any provider published a UTC cutoff.

Public evidence uses UTC calendar days and months. Convert timestamped source
evidence to UTC before extracting its date; keep chronology pending if an
unresolved artifact timezone could change the eligibility boundary. Eligibility
requires a lower bound strictly after the UTC safety bound. Dates at or before
the original cutoff upper bound are ineligible; the additional day remains
unresolved with reason `cutoff_timezone_boundary`. For a June 30 cutoff upper
bound, July 1 is unresolved and July 2 is the first eligible UTC date. A July-only
artifact likewise remains unresolved because its lower bound is July 1.

CVE IDs require ASCII digits and
canonical sequence numbers: four digits (including necessary leading zeros), or
more than four digits without a leading zero. Registry `identity_status` accepts
only `pinned_snapshot`, `documented_api_id`, or `documented_alias`; an unknown
status is invalid input. Documented aliases remain unresolved.
Nonfinite numbers, including exponent overflow such as `1e400`, are invalid input
and return exit 2 rather than an unresolved report.

A fix's author/committer timestamp or a CVE assignment/publication timestamp alone
does not establish earliest public disclosure. An observed artifact is an upper
bound on when exposure first occurred, until an earlier-evidence search supports
an earliest-evidence declaration. Pending records never receive an established
earliest-public-evidence lower bound. The helper validates the declaration's
structure and date arithmetic; it does not fetch sources, authenticate them, or
prove that the search was exhaustive. Temporal eligibility does not validate the
vulnerable revision, static label, source license, or scanner context.

## Current draft and maintenance

The [research dossier](research/recent-cve-candidates.json) records ten proposed
cases and the [chronology input](research/recent-cve-chronology.json) deliberately
keeps all ten pending. The proposed 2/3/3/2 split uses CNA-primary severity and
retains NVD disagreements in the dossier. These are research candidates outside
accepted corpus packs; no case was admitted, semantically approved, or scanned.
Observed dates and unvalidated fix-parent hypotheses are evidence to investigate.
Exclusions and reserves remain visible rather than filling quotas with unsupported
claims.

Maintenance is a repeatable review workflow, not a background scheduler:

1. Refresh primary provider documentation when a selected model changes and on
   each periodic corpus refresh. Record the retrieval date and source wording;
   keep unknowns, conflicts, and route changes explicit. Review registry diffs
   through Git so earlier snapshots remain recoverable.
2. Revisit advisories, public issues/PRs, releases, commits, and proofs of concept.
   Preserve observed publication separately from verified earliest chronology.
   Resolve CNA/NVD disagreements under the pack's declared authority.
3. Validate pinned vulnerable/fixed source and reporting locations through the
   corpus evidence workflow before any admission. Keep those decisions separate
   from this chronology-only report.
4. Run `model-cutoffs check` for the intended exact model set and save the report
   alongside that dated research update. An unknown cutoff or unresolved route
   blocks a universal claim and stays in the report. Rerun after new evidence.
5. Submit updated registry/dossiers and the deterministic validation evidence for
   review. Do not change `pending` to `reviewed` to make the quota pass.

[SASTBench section 3.1](https://arxiv.org/html/2601.02941v1) filters CVEs by a
configurable report-date cutoff, using February 2025 in the paper. The reviewed
earliest-public-artifact requirement here is a stricter ScanEval extension.
