# Model cutoffs and recent CVE eligibility

Issue: [#90](https://github.com/Har1sh-k/scaneval/issues/90).

## Problem and scope

A CVE assigned or published after a model's cutoff may describe a vulnerability
whose issue, patch, advisory, or proof of concept was already public. Provider
knowledge dates also need not describe the last training data used. ScanEval needs
an auditable dated registry and an offline, fail-closed chronology report, without
changing corpus admission or scanner execution.

The first registry covers researched current Anthropic, OpenAI, Z.ai GLM, and xAI
Grok text/code families. This is a dated evidence snapshot, not a guarantee of
exhaustive current availability. Source URLs and retrieval dates travel with each
model; provider wording, known precision, unresolved dates, aliases, and source
conflicts are retained. Exact API IDs are not automatically immutable revisions.

## Contract and decisions

- Store versioned packaged JSON. Each model has a provider, exact documented ID,
  source URLs, retrieval date, identity notes, and separate knowledge,
  reliable-knowledge, and training-data fields. Unknown fields remain null.
- A cutoff is a published day/month or a provider-supported temporal upper bound.
  Month end is computed conservatively and explicitly labeled an inference.
  Release dates and date-looking model names are never cutoff substitutes.
- Aliases are catalogued separately and never silently resolved by the helper.
  Callers select documented exact IDs after recording the actually served model
  and endpoint. Unknown IDs and known aliases return unresolved eligibility.
- `training` basis uses only a documented training-data cutoff/bound. `documented`
  basis prefers training, otherwise knowledge, otherwise reliable knowledge, and
  clearly reports the selected basis. The CLI defaults to `training`; a knowledge
  comparison cannot claim exclusion from training or absence of contamination.
- Input candidate records identify a unique CVE, one declared severity authority,
  severity, and chronology. Pending chronology is allowed and remains ineligible.
  Reviewed chronology must include the earliest public artifact date and precision,
  evidence URLs, and a review note explaining the earlier-evidence search. The
  helper checks this declaration structurally; it does not authenticate sources or
  independently prove there was no earlier artifact.
- Eligibility requires the earliest-public-evidence lower bound to be strictly
  later than the conservative cutoff upper bound. Equal, overlapping, unknown,
  pending, contradictory, and malformed inputs cannot yield eligibility.
- Report every selected model and every candidate. Pack completeness requires at
  least 10 distinct eligible CVEs and at least 2 Low, 3 Medium, 3 High, and 2 Critical
  under the selected authority across all selected models. A missing cutoff keeps
  cross-model eligibility unresolved. No count, date, or outcome admits a case.
- CLI is read-only with JSON stdout: `model-cutoffs list` and
  `model-cutoffs check CANDIDATES --model ID [--model ID] [--basis ...]`.
  `--registry PATH` supports reviewing a proposed registry update offline. Exit 0
  means the declared temporal pack target is met; 1 means valid unresolved or
  insufficient evidence/coverage; 2 means invalid input. No clocks, network calls,
  scanner/model execution, acceptance records, or automatic mutation occur.

## Research and maintenance

Commit draft recent-CVE dossiers only as research under `docs/research`; they
remain outside accepted corpus packs. Preserve authority conflicts and missing
pinned vulnerable/fixed source, semantic review, and chronology checks explicitly.
New records and candidate updates are ordinary reviewable changes: refresh primary
provider sources, retain retrieval dates and historical Git evidence, record routes
at execution, and rerun the deterministic CLI when any selected model changes.

[SASTBench](https://arxiv.org/html/2601.02941v1) uses a configurable CVE report-date
cutoff with February 2025 in the paper. The earliest-public-artifact check above is
ScanEval's stricter extension, not a requirement attributed to that paper.

## Validation and review

Tests cover exact/day/month boundaries (including leap years), training versus
knowledge, provider temporal bounds, unknown cutoffs, aliases, evidence gaps,
invalid dates/duplicates, full severity coverage and shortages, packaged data,
custom registry input, deterministic CLI results, and nonzero exit outcomes.
No paid scan is needed. Run focused tests and existing CLI regression coverage.

Use Elephant/Goldfish: retain this committed specification before implementation;
request a fresh Opus 5.5 reviewer on the resulting code and tests before publishing
a PR. The implementation agent does not perform that independent review.
