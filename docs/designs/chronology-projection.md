# Research dossier chronology projection

Issue: [#99](https://github.com/Har1sh-k/scaneval/issues/99).

## Problem and scope

The research dossier retains observed public evidence and severity decisions, but
the separate cutoff-check input currently requires manual transcription. Add
`model-cutoffs prepare-chronology DOSSIER --severity-authority TEXT` to print a
deterministic pending chronology document. This is an offline, read-only command:
no source retrieval, scanner/model calls, corpus admission, or file writes.
Exit 0 means projection succeeded; invalid input returns exit 2.

## Projection contract

- Accept only `scaneval.research-candidate-dossier.v1`. Validate consumed objects,
  unique canonical ASCII CVE IDs, required strings and structurally valid HTTP(S)
  source URLs. URL validation does not establish public reachability; perform no
  DNS, network, or private-address checks. Ignore unrelated research fields; they
  remain bound by the whole-dossier hash.
- Require an explicit nonempty severity authority from the caller. Retain each
  selected rating's authority, source, CVSS version, score and band. Accept CVSS
  3.0, 3.1 and 4.0, finite nonboolean numeric scores in 0.1–10.0 with at most one
  decimal place, and the standard Low/Medium/High/Critical boundaries. Selected
  severity and proposed stratum must agree with that score. This validates the
  selected rating, not the vector calculation or authority's factual correctness.
- Project only `dates.earliest_observed_public_evidence_at`, its corresponding
  source URL and explicitly declared native evidence kind. Policy v1 supports
  `maintainer_advisory_publication`, `public_release_publication`, and
  `public_pull_request_creation`. Unsupported kinds fail; there is no fallback to
  CVE publication, commit author/committer dates, titles, or URL-pattern guesses.
- Require a full timestamp with seconds and an explicit `Z` or numeric UTC offset.
  Accept an optional fractional second of one through six digits; reject longer
  fractions without rounding. Convert the timestamp to a UTC calendar day,
  preserve the original timestamp and native kind, and emit day precision. Reject
  missing/unknown timezones, invalid dates, offsets and out-of-range UTC
  conversions. Do not invent day precision for a source that supplies only a day
  or month.
- Retain the date note and optional evidence-scope caveat on the candidate
  artifact. The existing v1 `dates.related_predecessor` field explicitly
  represents a related advisory: retain its publication, URL, current-body update
  day and publication-wording flag, and mark the artifact `related_predecessor`.
  Its scope note retains the shared date note plus the predecessor relationship
  caveat, but not the candidate-only evidence-scope caveat. Require the recorded
  update day's UTC date to be on or after the predecessor publication timestamp's
  UTC date. Do not require predecessor publication to be on or before the
  candidate observation: an older weakness can receive a later advisory
  publication. The predecessor policy caveat states that publication does not
  establish contemporaneous wording or exact-weakness distinctness. This field
  mapping is versioned semantics, not inference from a URL. Composer therefore
  exposes its July 1 related observation without an established
  earliest-public-evidence lower bound.
- Every output chronology is `pending`, regardless of dossier claims about
  review, approval, completeness, or eligibility. Observations do not establish
  an earliest lower bound or training exclusion. The CLI does not certify that
  the selected source was public or the earlier-evidence search complete.
- Include `projection_provenance` with `policy_version`,
  `dossier_schema_version`, and `dossier_sha256`. Policy version is
  `scaneval.dossier-chronology.v1`; hash the complete parsed dossier using the
  existing canonical JSON digest (sorted keys, compact separators, UTF-8,
  nonfinite values rejected). The hash identifies input content, not authorship,
  truth, or source availability.
- The existing candidate validator accepts this optional provenance only with
  the supported versions, a lowercase SHA-256 digest, exactly the documented
  fields, and pending chronology. Preserve it unchanged in cutoff reports.
  Provenance is a caller-supplied binding; `check` cannot authenticate the dossier
  without reading it. Existing unbound standalone declarations remain supported.

## Validation and delivery

Test the actual ten-candidate dossier through prepare and check, including
Composer's predecessor, all-pending outcomes, observed dates, canonical source
hashes, deterministic/read-only output, and unchanged unbound-input behavior.
Exercise timestamp midnight offsets, ambiguous/invalid timezones, scalar and
unhashable malformed fields, duplicate IDs, unsupported kinds, missing sources,
contradictory/malformed severity, attempted status promotion, and malformed
provenance. Run focused cutoff and CLI tests. Commit this contract before code;
the root agent obtains the fresh Opus review before any PR.
