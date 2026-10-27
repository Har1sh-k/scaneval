# Condition preparation and evidence correctness

Status: reviewed for implementation; independent comprehension, design, and
readiness review completed before coding. Implementation verification is pending.

## Context and scope

ScanEval compares scanners over frozen source snapshots and evaluator labels. A
matrix schedules the same population under open-context, closed-book standard,
and identity-reduced conditions. Preparation creates scanner-visible trees;
condition evidence records what was actually enforced; reporting verifies the
saved evidence before giving detection credit. See [the matrix contract](../EXPERIMENT_MATRIX.md),
[open context](../OPEN_CONTEXT.md), [identity reduction](../IDENTITY_REDUCTION.md),
and [closed-book conditions](../CLOSED_BOOK.md).

This design resolves issues [80](https://github.com/Har1sh-k/scaneval/issues/80),
[81](https://github.com/Har1sh-k/scaneval/issues/81),
[82](https://github.com/Har1sh-k/scaneval/issues/82),
[83](https://github.com/Har1sh-k/scaneval/issues/83),
[84](https://github.com/Har1sh-k/scaneval/issues/84), and
[85](https://github.com/Har1sh-k/scaneval/issues/85). Their reproductions use
fabricated fixtures; none requires a real vulnerability scan or a model call.

An attested condition has the required verified evidence. Unavailable or failed
evidence must remain visible as missingness, never become a silent zero score.
The label contract is the case pack with only mechanical-check timestamps and
their derived digests normalized. It includes excluded and currently unplanned
cases because preparation can change their eligibility. A check set records
mechanical checks for a case and snapshot; its presence alone does not prove
that a recheck is idempotent.

Goals are to avoid predictable wasted scanner work, accept legitimate source
representations, keep retrieval records consistent, and enforce already-declared
rules. There is no new condition, scanner, wire schema, scoring rule, dependency,
network permission, identity obfuscation policy, or target execution.

## Chosen design

### 80: guard the prepared matrix cell before any scanner work

Move the existing `experiment_report.label_contract` implementation, unchanged
in meaning, into `experiment.py`. Retain the report module's importable name as
an alias for compatibility. Execution and reporting must share this definition;
neither may ignore all unplanned cases or broaden timestamp normalization.

Add an optional keyword-only `prepared_guard` to `runner.run_from_config`,
defaulting to `None`. It accepts the prepared pack and a schedule rebuilt from
that pack using the same configuration, selected inputs/systems, maps, and
creation time as the initial frozen schedule. Build this second schedule only
when a guard is supplied. Invoke the guard after all input preparation and the
runtime pack have been saved, before preparing any system or invoking an
adapter. It must sit outside the per-input exception handler: refusal fails the
cell using the existing run-manifest failure path.

`experiment_execution.execute` supplies a guard for each matrix cell. Require:

1. The prepared pack's normalized label contract equals the frozen matrix pack.
2. Every rebuilt schedule input has exactly the frozen population's schedule
   plan, and input/assignment membership and identities equal the frozen cell.

Reuse the schedule identity comparisons already in `_verify_run_semantics` by
extracting a shared pure helper rather than maintaining two subtly different
sets of rules. Keep the post-run verification as defense in depth. Do not
compare independently refreshed timestamps as meaningful schedule changes.

On refusal, raise `ContractError` explaining that preparation changed frozen
labels or eligibility and that the operator must run case checks, review the
resulting pack, and freeze a new matrix. The runtime pack, frozen schedule and
failed manifest remain available for diagnosis. An input preparation failure
with no pack/schedule drift retains the existing skipped-input behavior. If a
failed preparation mutated the pack, the same guard refuses the cell. Ordinary
non-matrix runs do not receive this new restriction.

All inputs of a cell are prepared before this check. Thus a later input cannot
allow an earlier input's scanner to start before drift is detected. Cells retain
the existing sequential execution and failure bookkeeping; this change does not
introduce a global two-phase executor or promise that other independently valid
cells never consume work when a later condition fails for an unrelated reason.

### 81: compare exact safe checkout representations

`open_context._source_binding` continues checking the exported tree digest, path
membership and executable modes. Replace the comparison of raw exported bytes
to stored blob IDs with a comparison to the exact checkout representation of
the evaluated commit. Cleaning arbitrary exported bytes is not sufficient:
Git's ident and line-ending conversions can map different working bytes to the
same stored blob.

Create an isolated temporary verification repository/worktree using the already
verified object store and a new HEAD-only index. Its configuration is generated
by ScanEval and all commands use `materialize.git_command` hardening. Use
portable `read-tree` and `checkout-index` plumbing, not a new minimum Git version
or repository hooks. The empty verification worktree obtains attributes from
the commit/index, never from scanner-visible working files. Do not copy the
source worktree, its configuration, filters, hooks, or live index.

Materialize only ordinary HEAD blobs (100644/100755), passing paths as NUL-delimited
stdin. Symbolic links and submodule entries retain the existing explicit omission
rules and must not be created or followed. Built-in eol, ident, and
working-tree-encoding conversions apply. No arbitrary filter command is
configured; unknown filter attributes remain inert, consistent with the
sanitized source checkout. Keep Git LFS handling inert as in materialization.
Hash the exact resulting bytes and compare them to the export. Refuse unsupported
conversion failures through `MaterializationError`, and remove the temporary
repository on every exit. Do not mutate the delivered history index, its stat
data, the source files, or the recorded attestation format.

The implementation must ensure all attribute lookup is rooted in the temporary
HEAD/index state, including nested `.gitattributes`, without writing symlinks.
Sharing objects may use a read-only temporary alternate to the verified object
store; it is private verification state and must never enter the scanner's
history artifact. This accepts the existing export bytes in all conditions;
there is no switch of ordinary exports to raw Git blobs.

### 82: redact the outer URL authority only

In `public_retrieval.recorded_url`, identify only the outer authority. For this
redaction step, skip leading ASCII whitespace/control characters when locating
the prefix, without deleting or normalizing them in the returned string. Accept
either initial `//` or a prefix ending in `://` whose preceding text contains
none of `/`, `?`, or `#`. Deliberately do not require a syntactically valid scheme:
malformed forms such as ` https://user:secret@host/` and
`ht tps://user:secret@host/` must still hide credentials before rejection.
The authority ends at the first `/`, `?`, or `#` after that prefix. Within it,
replace everything through the last `@` with `[redacted]@`. Preserve the rest
of the original string exactly, including nested URLs in path/query values.
Scheme-relative redirect authorities are supported; relative paths without an
authority are unchanged. Do not rely on `urlsplit` succeeding on malformed
credentialed input. Existing credential/control-character rejection remains in
`parse_url`; redaction runs before validation and must continue hiding userinfo
in both journals and returned diagnostics, including malformed userinfo.

No origin-policy or evidence-validator relaxation is permitted. Valid path/query
content must reach the existing hop comparison unchanged.

### 83: enforce the deadline below and above HTTP buffering

Keep the standard-library HTTP parser and the validated TLS connection. Add a
small private response/socket-file adapter in `public_retrieval.py` using
`io.RawIOBase` and `io.BufferedReader`. The raw reader owns the unbuffered file
returned by the actual TLS socket's `makefile('rb', buffering=0)`; it does not own
the connection socket. Before each raw `readinto`, compute the remaining
monotonic budget, fail if exhausted, and set the real socket timeout to
`min(TIMEOUT, remaining)`. Check the deadline again after a successful read.

The buffered reader checks the same deadline before/after its public reading
operations used by `HTTPResponse` (including readline, read, read1, readinto,
readinto1 and peek), so already buffered interim responses cannot bypass the
budget. Override the connection's response construction to pass this file
adapter into the standard `HTTPResponse`. Do not copy or rewrite HTTP parsing,
globally monkeypatch sockets, or introduce watchdog threads. Closing the response
must close its buffered/raw file exactly once and release the makefile reference;
the existing connection finally block still closes the actual socket.
`Recorder.retrieve` owns every successfully returned response: initialize its
per-hop reference before the request and close the returned response explicitly
in the per-hop `finally`, even on redirects, denials, timeouts and capture errors.
Use nested cleanup so connection closure still runs if response closure raises.
This covers `Connection: close` responses that `HTTPConnection` has detached
and can no longer close itself. Preserve standard-library cleanup when
`getresponse()` fails before returning a response. Update response test doubles
to implement `close`, and test unread detached redirects, detached body timeout,
and persistent-response cleanup with deterministic makefile/socket ownership.

The single deadline already created by `Recorder.retrieve` spans redirects,
headers, interim 100 responses, and body reads. Refresh the remaining budget
before TLS handshake after connection setup, and refuse an exhausted budget
before proceeding. Continue recording a terminal failed event on timeout. DNS
resolution remains the existing synchronous operation: this fix does not claim
that a blocked system resolver can be forcibly cancelled. Document that limit
instead of adding a process/thread subsystem.

### 84: align instruction-text classification and removal

In `blinding.removal_path_gap`, recognize case-insensitive extensionless
`instructions` in the `instruction_file` branch alongside the existing accepted
instruction-text names. Keep the earlier instruction-location checks, runtime
directory exclusion for configured aliases, protected-path checks, role checks,
review requirements and exact file hash requirements. Do not add `instructions`
to generic identity-document removal or permit editing instruction files.

### 85: reject explicit incompatible attestation mode

In `contracts._validate_condition_record`, the attested closed-book-standard
branch must reject explicit `mode == 'pr'`. Missing mode remains compatible with
historical documents. Non-attested PR condition records remain representable;
other condition branches retain their existing behavior. Improve the refusal
message to mention full-scan eligibility. This closes standalone semantic
validation inconsistency; runtime classification already refuses this mode.

## Alternatives and risks

- Ignoring excluded cases in reporting would mask runtime eligibility expansion.
  Checking only for an existing check set would miss stale checks. The prepared
  pack guard covers both without changing ordinary run semantics.
- Preparing all matrix cells in a new global transaction would be a broader
  runner redesign. The guard uses the existing all-input preparation boundary.
- Normalizing exported bytes back into Git blobs can hide alterations. Comparing
  expected checkout bytes preserves exactness at the cost of temporary I/O.
  The existing export already requires disk proportional to snapshot size; the
  temporary verification checkout adds one such copy and is promptly removed.
- Applying original repository filters can execute untrusted programs. A fresh
  configuration and isolated HEAD/index state permit only built-in conversions.
- Generic URL parsing can fail before credentials are removed. A bounded outer
  authority scan preserves malformed-userinfo handling without rewriting paths.
- A timeout checked only after `getresponse` cannot stop slow headers. Per-line
  checks alone cannot stop a single trickled line. Raw and buffered read checks
  cover both while keeping the standard parser and socket ownership rules.
- The retrieval implementation is copied into a standalone Python container;
  it must retain standard-library-only imports and work on Python 3.11–3.13.
- New attestation rules must not silently invalidate compatible omitted fields
  or hide failed/skipped observations. No score becomes more favorable through
  exclusion or normalization changes.

## Implementation phases and acceptance tests

Commit this reviewed specification first. Then make a separate logical commit
for each issue, including its regression tests and relevant user documentation.
Three disjoint work streams are matrix preparation, open-context history/retrieval,
and identity/condition validation. No result bundles or machine-local artifacts
belong in Git. Commits use the configured repository author and no AI co-author
trailers.

| Issue | Primary code | Required regression behavior |
| --- | --- | --- |
| 80 | experiment.py, experiment_execution.py, experiment_report.py, runner.py | Valid baseline and timestamp refresh run; unchecked excluded case, failing draft, newly eligible draft and stale checks refuse before any adapter preparation/invocation; later-input drift also has zero calls; ordinary runner and unchanged skipped inputs retain behavior. |
| 81 | open_context.py | Real local two-commit CRLF/ident/UTF-16 and nested-attribute fixtures pass export, attestation and installation; changed bytes including normalized-away ident/EOL changes, changed mode, altered attributes, and malformed encoding refuse; malicious configured filter/hook is not executed; symlink/gitlink omissions remain explicit. |
| 82 | isolation/public_retrieval.py | Real recorder/capture/classifier fixtures accept query/path nested URLs and relative redirects; actual outer credentials remain absent from both journals and returned diagnostics; leading-space/control prefixes, malformed schemes and scheme-relative userinfo stay redacted and denied. |
| 83 | isolation/public_retrieval.py | Real HTTPResponse parser on bounded deterministic transport times out during slow status/header bytes and repeated 100 Continue; buffered input checks use the same deadline; fast control succeeds; failure completion is journaled; body/chunk framing, TLS timeout and close/refcount behavior remain correct. |
| 84 | blinding.py | Reviewed strict maps remove extensionless known/nested/configured instruction text and record removal; .md control succeeds; runtime source aliases, wrong role, stale hash, missing review and unsafe paths still refuse. |
| 85 | contracts.py | Direct validator and CLI reject attested closed-book explicit PR; full, omitted-mode and non-attested PR controls remain accepted; runtime reclassification still refuses inconsistent records. |

Matrix guard regressions must use a complete fabricated pack and the actual
runner, with counting adapters. Existing incomplete frozen-shell or mocked-runner
fixtures do not exercise preparation or this guard and are insufficient alone.

Extend existing test modules for experiment execution/reporting, open context,
public retrieval/evidence, identity exports/policy, conditions and contracts.
Use pure fabricated fixtures and no paid-model or real-CVE scans. Keep the
existing documented three-condition Semgrep Docker test as the successful
end-to-end control. Drift refusals need counting adapters, not extra Docker scans.

## Review and merge gates

The process uses [Elephant/Goldfish](https://github.com/google/elephant-goldfish-model):
the coordinator retains requirements, while fresh reviewers evaluate the artifact
without earlier review conclusions. Review comprehension/simplicity, design risks,
and implementation readiness before coding. After implementation, use new
reviewers against this spec and the code; resolve substantive findings and repeat
with fresh context. Update this living spec if an accepted design changes.

Before merging, independently inspect the diff and regression evidence, check
that all six issues have tests, run focused Python tests and the synthetic
Semgrep matrix, and require successful exact-head CI (Python 3.11/3.13, TypeScript,
wheel/demo replay, and real Docker). Preserve logical commits with a merge commit.
Verify main contains the reviewed tree and its post-merge CI succeeds. Preserve
unrelated work in other checkouts. No additional human approval is required for
this implementation/merge because the user explicitly delegated both.
