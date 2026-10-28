# Codex quota guard for operator experiments

Status: implementation and both reviews' required corrections are implemented
and tested; the second review's correction awaits a fresh independent review.
Public feature request:
[#91](https://github.com/Har1sh-k/scaneval/issues/91). Code review is reserved for
a fresh Opus 5.5 reviewer before any PR; this document does not claim review
approval. See [operator usage and limitations](../CODEX_QUOTA_GUARD.md).

## Scope and invariant

Add a standalone, standard-library POSIX operator utility at
`tools/codex_quota_guard.py`. It wraps one explicitly supplied command, starts
that command in an owned process group, and allows it to run only while every
reported Codex quota window satisfies `1 < remaining_percent < 90`. Require a
weekly (10080 minute) window so that a short-window reading cannot silently
replace the experiment's weekly budget. A null secondary window is allowed;
missing/malformed readings or a changed set/duration of windows are not.

The first valid reading establishes the baseline. Every later accepted reading
must have the same window reset timestamps and no increase in remaining quota.
Stop at a known reset deadline even if the next endpoint response has not
arrived. A reset, quota increase, either inclusive boundary, lost usage access,
malformed response, read timeout, stale local observation, interruption, runtime
deadline, or audit-write failure is terminal. Never automatically restart the
experiment after a refusal.

## Read-only quota source

Use the installed `codex app-server --listen stdio://`, with the ordinary
`initialize` / `initialized` handshake, then
`account/rateLimits/read` with `excludeResetCreditDetails: true`. Do not create
threads or turns, consume reset credits, request fallback reserve exposure,
read auth files, print account details, or issue model requests. Discard
app-server stderr and unrelated notifications. Bound transport buffers, total
request time, and subprocess cleanup. A protocol failure does not trigger a
retry or an alternative model call.

This contract was checked against the locally installed Codex CLI 0.165.0
generated JSON schema. `usedPercent` is an integer, `resetsAt` is Unix seconds,
and `windowDurationMins` identifies the window. Select the explicitly configured `--limit-id` bucket (default `codex`) from
`rateLimitsByLimitId`; require an exact `limitId` match in both mapped and legacy
responses. Missing/malformed selected data never falls back. Record sorted visible
bucket keys and whether a bucket map was present. An absent or null map leaves
other quota windows unknown: refuse with `bucket_map_unavailable` unless the
operator explicitly supplies `--allow-other-limit-windows`. A permitted legacy
response still records `bucket_map_present: false` and
`bucket_visibility_available: false`; its one identifier does not establish
complete bucket visibility. Malformed maps remain invalid even with the exception.
Other reported quota windows require an explicit
`--allow-other-limit-windows` exception; the workload model's charged bucket is not
proven merely by an account catalog. Credits and other model quotas do not
override the selected window checks. Official protocol reference:
<https://learn.chatgpt.com/docs/app-server>.

## Timers, containment, and audit

Default poll interval: 30 seconds; read timeout: 10 seconds; maximum local
observation age: 45 seconds. Configuration has finite, positive upper bounds
(poll at most 60 seconds, read at most 30 seconds, local age at most 120 seconds)
and must leave enough freshness time for a scheduled read. Require a bounded
overall runtime (default six hours, at most one day). Check reset/freshness/
runtime deadlines while waiting for both responses and command completion.

Terminate only the command's registered process group and the owned app-server
group, first with TERM, then KILL after a bounded grace period. Never search for
or kill processes by name, scan other sessions, or terminate unrelated Codex or
Claude work. Clean up descendants even when the direct command exits. Detached
processes that leave the owned group are outside this utility's containment
contract and must not be used by the wrapped job.

Keep owned leaders unreaped until group cleanup using POSIX `waitid(WNOWAIT)`.
Darwin may report EPERM when a group contains only its dead leader; accept that
case only after a bounded `PROC_PGRP_ONLY` query positively identifies that exact
group as containing just the unreaped leader. A live group, failed query or
possibly truncated query remains a cleanup failure.

Docker work must register exact full container IDs or explicitly supplied
Docker `--cidfile` paths. Read those paths during monitoring and immediately
before cleanup; freeze each observed ID, reject changes/malformed files, and
stop only the registered IDs with bounded Docker calls. No container discovery,
prefix matches, label sweeps, pruning, default deletion, or arbitrary PID attachment.
An unregistered detached container is outside the contract. The operator must
ensure every experiment container is registered before it consumes quota.

A controller may instead atomically maintain a bounded append-only registry:
`{"schema":1,"container_ids":["<full ID>"]}`. Accept initially absent files,
then require monotonically growing ID membership; reject invalid/deleted or
symlinked files. Maximum 2,048 entries / 256 KiB. This provides dynamic explicit
registration without Docker discovery.

For ephemeral workloads using detached Docker clients, provide explicit
`--stop-file` and `--remove-containers` options. Create the private, initially
absent stop marker before child/container cleanup. The scoped Docker wrapper
must reject create/start after that marker, register each full ID before start,
and start by inspected immutable ID. The opt-in removal action forcibly removes
only the registered IDs, closing the race where a detached start could restart
a merely stopped container after guard exit. A pending start therefore either
runs before removal and is killed, or fails after removal. Marker failure is
visible, never skips remaining cleanup, and prevents cleanup-success reporting.
No unregistered container may be removed. The root coordinator explicitly
authorized this option for owned ephemeral experiment containers.

Batch-stop registered IDs, then on a failed stop inspect only exact registered
IDs with a format exposing ID and running status. Accept already-removed IDs
only after an exact missing-container diagnostic and a successful daemon
version query; connection failure or unverified state remains cleanup failure.
Use five-second per-call deadlines and a ten-second aggregate Docker cleanup
budget, plus bounded client-process cleanup. Preserve full IDs and each
stopped/removed/not-found/still-running/not-removed/unverified state in the final
audit receipt; an existing stopped container fails a requested removal.

Write an exclusive new mode-0600 JSONL receipt file. Receipts contain an
allowlisted schema of timestamps, window percentages/durations/reset times,
terminal reason codes, process-group IDs, exit status, full explicitly
registered container IDs, per-container cleanup states, and cleanup counts.
Never persist raw protocol payloads, errors, prompts, command arguments,
environment, tokens, auth state, account identity, or child output in receipts.
Keep experiment output on its own normal streams. Any receipt failure stops
the owned work. Unknown exceptions produce a fixed sanitized failure reason.

## Limits and acceptance evidence

Whole-percent reporting, upstream reporting delay, already accepted/in-flight
requests, and consumption by other sessions prevent a hard remaining-token
guarantee. The endpoint has no source observation timestamp: local request
freshness is enforced, but upstream cache freshness cannot be established.
Identical successful readings are not themselves evidence of stale data. A
guard killed with SIGKILL, machine suspension/failure, detached processes, or
unregistered containers cannot be controlled by a userspace monitor.

Use fabricated endpoint/process fixtures only. Tests must demonstrate:

- strict threshold refusal before launch; valid, equal and decreasing remaining
  quota; upward movement and changed/elapsed resets stop;
- missing, malformed, ambiguous, changed-window, stale and unavailable readings
  fail closed, including blocked or noisy transport;
- deadline enforcement while a read is pending and while the job is running;
- TERM/KILL cleanup of an owned process group including stubborn descendants,
  with unrelated process survival;
- exact container registration and bounded cleanup with no broad discovery;
- sanitized receipts and protocol calls limited to the handshake and usage read;
- successful command exit, nonzero command exit and signal interruption.

Follow Elephant/Goldfish artifact separation: commit this specification first,
then logical implementation/test/documentation commits. Use the configured Git
author without AI co-author trailers. Preserve the existing dirty checkout.
Do not run scans, push, open a PR, or perform code review in this work stream.

Implementation validation after the second-review correction: the three quota
guard/wrapper test files pass 202 synthetic tests, covering policies, transports, ownership,
registry evolution, Docker cleanup proofs, stop-marker ordering, and opt-in
exact-ID removal. Repository hygiene checks pass two tests with one existing
skip. A harmless real Docker integration also verified the permanent stop marker,
exact registered-container removal (including a previously removed ID), and
owned-process cleanup. No model calls or scans were used for this evidence.
Fresh Opus 5.5 review of the second-review correction remains the next gate.

## Review corrections before live use

The first independent Opus review identified three required corrections. Complete
these before a fresh review or any model workload:

- Treat SIGINT, SIGTERM, SIGHUP and SIGQUIT as controlled interruptions. Each must
  close the stop gate and clean up owned process groups and registered containers.
- Verify failed Docker cleanup with one bounded batch inspect over the exact
  registered IDs, rather than one process per historical container. Account for
  each ID exactly once via a well-formed ID/running JSON line or an exact
  missing-container diagnostic; a separate successful daemon-version read is
  required for missing IDs. Duplicate, unexpected and incomplete accounting
  remains unverified. Support at most 2,048 registered containers in a 256 KiB
  registry in both guard and wrapper. This is an explicit per-run budget; it is
  large enough for repeated worker/proxy/probe creation across a 50-case run,
  while keeping the full-ID command line bounded.
- Select quota explicitly with `--limit-id` (default `codex`), require the selected
  bucket's `limitId` to match, and record the selection and visible bucket keys.
  Other buckets containing windows cause refusal unless the operator explicitly
  supplies `--allow-other-limit-windows`; the exception must remain visible in
  receipts. This makes unaccounted model-specific quota an explicit decision.

Dynamic registry mode requires `--container-registry`, `--stop-file`, and
`--remove-containers` together, and an absolute real Docker executable. Validate
control-path parents before starting any workload: they must already exist,
belong to the current user, and prohibit group/other writes. Existing registry
files must be bounded regular files with one link, the current owner, and no
group/other write permission. Apply the same checks in the launch wrapper; do
not weaken them for shared `/tmp`. The operator creates a private directory.

Add regression coverage for hangup/quit cleanup, mixed existing/missing batch
results, ambiguous/duplicate/foreign diagnostics, capacity, bucket selection and
visibility, unsafe parents/registry metadata, and missing dynamic-mode coupling.
Then run a harmless real Docker workload on the dedicated test engine, including
one already-removed registered ID and one sleeping container. Require a permanent
stop marker, exact owned-ID removal, no surviving owned group, and retained
sanitized receipts. This integration calls no model; quota reads are read-only.

The second review requires missing/null bucket-map refusal, an explicit legacy
exception, and truthful map-presence/visibility fields on accepted and rejected
readings. Regression tests must prove a legacy response cannot launch work by
default, that the exception remains audited, and that full-map receipts differ
from legacy receipts. Refuse Docker create names consisting of 64 lowercase hex
characters, so a wrapper-created name cannot be mistaken for a full container ID.
