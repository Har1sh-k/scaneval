# Claimed severity calibration (issue #60)

This specification is the persistent implementation brief (Elephant). A fresh Opus 5.5
session receives this brief and the final diff for independent review (Goldfish), before a PR.

## Scope and invariants

Add `scaneval severity RUN... --pack PACK --output REPORT [--html HTML] [--policy POLICY]`
and `--verify REPORT` replay. Read saved runs only; never call a scanner, change detection
credit, rewrite decisions, create approvals, or fetch reference ratings implicitly.

Use the existing frozen schedules, canonical target identity, saved adjudication bindings,
and aggregation weighting policy. The supplied pack must exactly match every frozen pack.
Only successful, resolved observations with current `human_approved` finding reviews and
an accepted claim for that target enter calibration. Draft/probable/unresolved, partial,
unsupported, failed, missing and stale observations remain explicit exclusions. This
approval is an existing saved-record claim, not authenticated reviewer identity.

Count a canonical target once per observation. Select the directly accepted claim with the
lowest native rank, then claim ID; for unranked output select by claim ID. Selection never
looks at severity. Merge aliases before selecting. Repetitions average within run/input,
then run/input means average within canonical targets before target/project/family weighting;
they do not inflate target weight.
Separate systems, modes, profiles and declared/evidenced condition strata.

## Evidence and comparisons

Preserve native severity text exactly. Normalize only case/outer whitespace for the declared
labels `none`, `low`, `medium`, `high`, `critical`. Other labels are unavailable; confidence,
rule priority and SARIF error/warning labels are not CVSS. Never invent a numeric score.

Add optional `claimed_cvss` to 2.1 scan claims: explicit numeric score, version (3.0/3.1/4.0),
provenance (`native`, `imported`, `self_reported`) and optional original vector. Existing
2.0/2.1 records remain readable. Numeric claims require one-decimal scores from 0 to 10;
vectors, when supplied, must be structurally complete, valid base vectors for that version.
Do not calculate a score from code, prose or vectors. Do not claim that syntax validation
checks the arithmetic relationship of a vector and a supplied score.

The frozen pack's `severity` is the selected reference. Keep score, vector, version, source,
source kind, retrieved date, note (including disagreement), and explicit selection policy:
use the pack-selected reference without substituting a different authority. Preserve all
alias references. Conflicting reference records for one canonical target make comparison
unavailable instead of selecting whichever improves agreement.

For 3.0/3.1/4.0 the ordered bands are none, low, medium, high, critical with boundaries
0; 0.1–3.9; 4.0–6.9; 7.0–8.9; 9.0–10.0 (FIRST specifications). Numeric comparisons
require identical versions. Cross-version numeric values are retained, flagged and excluded
from numeric and ordinal comparisons; qualitative claims compare against the reference scale.
When both native label and numeric claim map to different bands, exclude as conflicting.

## Output and replay

Produce strict machine-readable output and escaped standalone HTML with per-target records,
references, selected claim, raw label/numeric evidence, band error, outcome, numeric delta,
and exact reasons for unavailability/exclusion. Bind to full result, plan, decisions, review
record, pack, target definition, reference and policy digests. Replay recomputes everything;
any changed evidence invalidates the old report. No cached output is trusted as current.

Show assessed, unavailable, excluded, total matched and scheduled target observations;
coverage, exact/over/under rates, band error distribution/MAE, numeric bias/MAE, denominators,
missingness reasons and CVSS-version strata. Show canonical target counts separately from
observation counts. Use existing workload weighting restrictions. No calibration confidence
intervals or promotion gates in this change.

## Required verification

Meaningful tests: exact/over/under, numeric and qualitative, boundary values, missing/unknown
labels, invalid numbers/vectors, cross-version, conflicting inputs/references, duplicate
claims/aliases, repetitions/weighting, unaccepted claims, review/status exclusions, stale
bindings, escaped HTML and CLI replay. Existing detection outputs must remain unchanged.
Run relevant contract, aggregation, review, scorer and CLI tests; build TypeScript SDK if its
types change. Save actual Opus review receipts outside version control, resolve findings and
repeat fresh review before creating the PR. Do not add coauthor trailers or experiment output.

Sources: https://www.first.org/cvss/v3.1/specification-document and
https://www.first.org/cvss/v4.0/specification-document. CVSS 2.0 is outside the current
corpus severity contract and remains explicitly unsupported.
