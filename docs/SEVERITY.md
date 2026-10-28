# Severity calibration

`scaneval severity` compares a scanner's claimed severity with the **reference CVSS**
selected in a frozen case pack, after the finding has been accepted for that target.
It reads saved evidence only. It does not award detection credit, judge a finding,
change recall or precision, or affect promotion gates.

```sh
scaneval severity results/run-a results/run-b --pack corpus/diverse/pack.json \
  --output reports/severity.json --html reports/severity.html
scaneval severity results/run-a results/run-b --pack corpus/diverse/pack.json \
  --verify reports/severity.json
```

Both output paths must be new and outside saved runs and materialized trials. The pack
must match the configured-pack hash in every schedule. The runtime `evaluator/pack.json`
may differ through mechanical checks and newly recorded tree hashes; its full hash is
recorded separately and must match each plan. Labels, severity, review history and any
already-declared tree hashes must agree across both copies. Use `--policy` with an existing aggregation
policy for declared workload or explicit target weights. Replay uses the saved policy and
returns exit 2 if any evidence or derived result no longer agrees; it performs no scan.

## Eligibility and missingness

Only successful, resolved observations with reviewed label scope, current recorded
`human_approved` finding decisions and a directly accepted claim enter severity calibration. This records a review
assertion; it does not authenticate a person. The command never manufactures approval.
Draft, stale, missing, unresolved, unmatched, unsupported, partial and failed observations
remain excluded with reasons. Accepted findings on partial runs may have detection credit
under the existing detection rules, but do not enter this feature's severity denominator.

Missing reference or claimed severity is **unavailable**, never zero. Reports include total
scheduled target observations, accepted matches (including excluded matches), eligible
matched observations, assessed, unavailable and excluded counts. Canonical target counts
are separate from observation counts. No targets can be reconstructed from an unavailable
frozen plan; its assignment is listed explicitly in `unplanned_assignments`, with scheduled
and unplanned assignment counts. Draft and diagnostic evidence have separate scope strata
and are excluded from official calibration.

## What is compared

The claim's `native_severity` is retained exactly. The built-in mapping recognizes only
`none`, `low`, `medium`, `high`, and `critical`, ignoring case and outer whitespace.
`bug`, `warning`, `error`, `informational`, rule priority and confidence are not mapped.
There is no numeric conversion of a qualitative label.

A 2.1 scan-result claim may optionally carry:

```json
{"claimed_cvss":{"score":8.2,"version":"3.1","provenance":"native"}}
```

The score must be an actual scanner-supplied CVSS base score, with version `3.0`, `3.1`
or `4.0` and provenance `native`, `imported` or `self_reported`. An optional `vector`
preserves the original complete base vector. Structural validation rejects missing,
duplicate and invalid metrics and version mismatch. **Scores are not recalculated from
vectors**; syntax validity is not a claim of arithmetic consistency. Temporal/environmental
vector extensions and CVSS 2.0 are unsupported. Existing adapters continue to supply their
original qualitative labels; this change does not infer numeric scores from their output.

The reference record preserves the pack-selected score, vector, version, source URL,
source kind, retrieval date and note. The explicit selection rule is to keep that frozen
selection, including the note describing source disagreements. The command does not fetch
or silently substitute a newer CNA, vendor or NVD score. All reference records for aliases
remain visible. Different scores, versions or vectors for one canonical target make the
comparison unavailable; equivalent ratings use the lowest case ID's reference while retaining
every source. A missing alias reference also remains unavailable.

For CVSS 3.0, 3.1 and 4.0, the ordered bands are None (0), Low (0.1–3.9), Medium
(4.0–6.9), High (7.0–8.9), Critical (9.0–10.0), following the
[FIRST 3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and
[FIRST 4.0 specification](https://www.first.org/cvss/v4.0/specification-document).

| Reference | Claimed evidence | Band error | Numeric delta |
|---|---|---|---|
| CVSS 3.1, 9.1, Critical | Native `High` | −1, underestimated | Unavailable: qualitative only |
| CVSS 3.1, 9.1, Critical | CVSS 3.1, 8.2 | −1, underestimated | −0.9 |
| CVSS 3.1, 9.1, Critical | CVSS 4.0, 8.2 | Unavailable: version mismatch | Unavailable: version mismatch |

If a numeric claim and a recognized native label disagree on the band, both remain in
the evidence and calibration is unavailable. An unmapped label does not invalidate an
otherwise explicit numeric CVSS claim, but is preserved as originally supplied.

## Selection, weighting and provenance

Each canonical target receives one comparison per scheduled observation. Among directly
accepted claims, select the lowest native rank and then claim ID; for unranked output use
claim ID. Selection never looks for the claim whose severity best matches the reference.
Consequently a first accepted claim with missing severity stays missing even when a later
accepted claim has one. Duplicate findings and aliases cannot increase target weight.

Repetitions average within each run/input, then those run/input means average within a
canonical target. Target, project, family and explicit weighting use the same declared
aggregation policy as detection. Mixed workloads require declared workload weights.
Systems, modes, identity profiles, condition names and condition evidence states have
separate views. Reports include assessment coverage, exact/over/under rates, ordinal error
distribution and mean absolute error, numeric bias and mean absolute error, raw and weighted
denominators, and version strata. Version strata include excluded rows as well as assessed ones; absent or conflicting
reference versions have explicit `unavailable` or `conflicting` strata. No confidence intervals are produced.

Every report binds full results, plans, decisions, review records, target definitions,
references, pack, schedules, manifests, configurations and policy by canonical hashes.
`--verify` recomputes from the supplied runs and pack; the presence of a saved comparison
alone is never proof it is still current. HTML escapes scanner-controlled content and
contains no script or remote resource requests.
