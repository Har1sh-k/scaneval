# Operator Codex quota guard

`tools/codex_quota_guard.py` supervises one command and stops its owned process
group when Codex usage leaves the allowed range. It is an optional operator
utility, separate from ScanEval's scanner contracts and benchmark results.
Python 3.11+ and a POSIX platform with `waitid(WNOWAIT)` are required. The
protocol was checked against the installed Codex CLI 0.165.0 schema.

The monitor starts `codex app-server`, performs the initialization handshake,
then calls only `account/rateLimits/read` with
`excludeResetCreditDetails: true`. It uses the installed CLI's existing account
access. It does not read auth files, start model turns, consume reset credits,
or opt into reserve fallback. An unavailable account read prevents launch.

## Run a command

For a harmless local demonstration after signing in to Codex normally:

```sh
python3 tools/codex_quota_guard.py \
  --receipts /tmp/quota-guard-demo.jsonl \
  --max-runtime-seconds 120 \
  -- python3 -c 'import time; time.sleep(60)'
```

Use a new receipt path for every invocation; existing files and symlinks are
refused. Replace the command after `--` with the authorized workload. The
command inherits its normal environment, working directory and output streams.
The guard never writes command arguments, output or environment into receipts.

The first valid read must include a weekly window (10080 minutes), and every
present Codex window must satisfy **`1 < remaining_percent < 90`**. A null
secondary window is accepted. Subsequent readings must preserve the set of
windows, their durations and reset timestamps; remaining quota may stay equal
or decline. Any increase, reset change, elapsed reset, boundary crossing,
missing/malformed response, or read failure stops the command. There are no
automatic retries or restarts after a terminal refusal.

The default timers are:

| Timer | Default | Allowed range |
| --- | --- | --- |
| Poll interval | 30 seconds | 0.1–60 seconds |
| Each usage read or initialization timeout | 10 seconds | 0.1–30 seconds |
| Maximum age of a locally accepted read | 45 seconds | 0.2–120 seconds |
| Overall runtime, including initialization | 6 hours | 0.1 seconds–24 hours |
| TERM-to-KILL grace for each owned process group | 3 seconds | 0.1–10 seconds |

Use `--poll-seconds`, `--read-timeout-seconds`, `--stale-after-seconds`,
`--max-runtime-seconds`, and `--grace-seconds` to configure these bounds. The
stale age must be greater than poll interval plus read timeout. Known reset,
staleness, runtime and interruption deadlines are checked at most every 0.1
seconds while waiting for the next poll or a usage response, subject to OS
scheduling. A blocked read therefore cannot postpone a known reset deadline.

## Process and container ownership

The command runs in a newly created process group. On every exit, the guard
sends TERM, then KILL after the grace period, to that group and its own
app-server group. It keeps direct children unreaped until group cleanup to
prevent process-group ID reuse. On macOS, an EPERM for a group containing only
the dead leader is verified through a bounded query of that exact group.
Other permission failures are reported as cleanup failures. It never attaches
to arbitrary PIDs or kills processes by program name.

All quota-consuming subprocesses must remain in the owned group. Jobs that
start new sessions/process groups, daemonize, schedule independent remote work,
or start unregistered containers need their own explicit containment. In
particular, wrapping a runner that creates detached scanner groups alone is
insufficient. Do not use this guard as a substitute for that runner's cleanup.

Docker containers survive their Docker client process, so register every
experiment container explicitly. Use repeated `--container-id` arguments with
complete 64-character lowercase hexadecimal IDs, or reserve initially absent
files using repeated `--container-cidfile` arguments and pass the same paths to
the workload's Docker `--cidfile` options. Each cidfile must contain one full ID.
The guard freezes an ID once observed and refuses a changed or malformed file.
It refreshes cidfiles at polls and after stopping the owned command group.

For a controller that creates containers dynamically, use
`--container-registry /path/to/registry.json`. The operator-owned registry has
this shape:

```json
{"schema": 1, "container_ids": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]}
```

The file may initially be absent or contain an empty list. The controller must
register each full ID before forwarding the corresponding container start,
using a writer lock and atomic replacement to append IDs. Once observed, IDs
must never disappear from the list; they remain in the audit even after Docker
removes the container. Malformed files, deletion after observation, symlinks,
more than 256 entries, or files larger than 64 KiB fail closed. This is an
explicit registration channel; the guard does not search labels or enumerate
containers.

For workloads with detached Docker clients, configure both `--stop-file PATH`
and `--remove-containers`. The marker must initially be absent. The guard
creates it with mode 0600 before terminating any owned process or cleaning up
containers. A scoped wrapper must reject new create/start calls once the marker
exists, register create IDs before permitting start, and forward start using
the inspected full ID. The explicit removal option then runs
`docker container rm --force -- <exact registered IDs>`: a delayed start either
precedes removal and is killed, or follows removal and fails because that
immutable container ID no longer exists. Stop alone does not prevent delayed
restarts. Use removal only for explicitly registered ephemeral containers;
their writable container layers are deleted. Unregistered containers are
never targeted. The operator chooses the real Docker executable with
`--docker`, while the workload can use its scoped wrapper on PATH.

On exit it runs one bounded `docker container stop --time 0 -- <exact IDs>`
command for the registrations, including when the experiment command exits
normally, unless explicit removal was selected. It never discovers or prunes
containers. If the selected cleanup command fails, it inspects only the exact
registered IDs and only their ID/running
fields. Already removed containers count as `not_found` only when Docker
returns an exact missing-container error and a separate daemon-version read
succeeds. Connection errors, mismatched inspection IDs, and still-running
containers remain failures. Each control call has a five-second deadline,
with a shared ten-second cleanup budget plus bounded client-process cleanup.
The final receipt preserves every ID and its `stopped`, `removed`, `not_found`,
`still_running`, `not_removed`, or `unverified` state. An existing stopped
container is a cleanup failure when removal was requested. Keep cidfiles and
the append-only registry until the guard finishes. Stop-marker creation
failure is reported and cleanup is still attempted, but the wrapper's start
gate cannot be certified closed. The marker remains after exit; every new
guard invocation needs a fresh marker path.

## Receipts and exit codes

The new JSONL file is created with mode 0600. Records include accepted/rejected
percentages, window durations/reset times, monitor timers, owned command group,
terminal reason, command exit code and cleanup status. Raw responses,
notifications, upstream error text, app-server stderr, account details,
credentials, command arguments and child output are excluded.
Full explicitly registered container IDs are included for cleanup auditing.

Successful completion preserves the command's exit code. A guard refusal or
cleanup failure exits 125; SIGINT/SIGTERM requests a controlled stop with exit
130, unless cleanup fails. A command killed by a signal maps to `128 + signal`.
Inspect `guard_stopped.reason` and `cleanup_okay`, since a wrapped command may
itself return 125 or 130. A receipt write failure still stops owned work, but
the failed receipt destination may be unable to record that stop. Keep the
process exit status as part of operator evidence.

## Accuracy and operational limits

The endpoint reports whole percentages. Reporting delay, other account activity
and requests already in flight mean the guard cannot guarantee an exact token
reserve or prevent overshoot between readings. Stopping local processes also
cannot retract a request already accepted upstream.

The usage response has no source observation timestamp. The guard enforces
fresh successful request/response cycles and local age, but cannot prove the
upstream data is uncached. Equal consecutive percentages are allowed. The
receipt explicitly reports `upstream_observation_time_available: false`.

A userspace monitor cannot enforce deadlines while suspended or after its own
SIGKILL, a host failure, or a blocked filesystem operation. Keep receipts and
cidfiles on responsive local storage. Resume detects elapsed reset/freshness
deadlines, but cannot undo work completed while the guard was unscheduled.

Validation uses fabricated endpoints and local synthetic child processes only:

```sh
python3 -m pytest tests/test_codex_quota_guard.py -q
```

The [committed specification](designs/codex-quota-guard.md) records the scope
and acceptance requirements. Fresh Opus 5.5 code review is required before PR.
