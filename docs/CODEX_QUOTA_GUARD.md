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

For a long-running interactive job, use a `tmux` session and detach from it while
the guard runs. `nohup` does not make the guard immune to SIGHUP: the guard
installs its own SIGHUP handler, so a received hangup still requests cleanup.

Select the exact quota bucket with `--limit-id` (default `codex`). The selected
bucket must report the same `limitId`, including legacy responses; a map missing
the requested bucket cannot fall back to another entry. The first valid read
must include a weekly window (10080 minutes), and every present selected window must satisfy **`1 < remaining_percent < 90`**. A null
secondary window is accepted. Subsequent readings must preserve the set of
windows, their durations and reset timestamps; remaining quota may stay equal
or decline. Any increase, reset change, elapsed reset, boundary crossing,
missing/malformed response, or read failure stops the command. There are no
automatic retries or restarts after a terminal refusal.

Sorted visible bucket keys and the selected bucket ID appear in startup and usage
receipts, together with `bucket_map_present` and `bucket_visibility_available`.
An absent or null bucket map refuses launch with `bucket_map_unavailable`: a
legacy response's single bucket does not show whether other windows exist.
Other buckets reporting primary/secondary windows refuse launch by
default: the guard cannot establish which bucket a particular model request will
spend. An informed operator may explicitly set `--allow-other-limit-windows`;
this exception permits a legacy response and is recorded. Legacy receipts keep
both map-presence and visibility fields false; malformed maps and windows still
fail closed. A full bucket map containing only `codex` establishes the visible
account selection but does not prove that GPT-5.6 Sol or any other model charges
that bucket. Model
billing/quota identity remains unverified without independent provider evidence.

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
Local freshness starts when a usage request starts, so its age includes the
time spent waiting for that response. Consecutive slow reads can reach the
staleness deadline during a later read even when each request stays within its
individual timeout. That cutoff fails closed; a response does not restart the
age of the data from zero.

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
Place cidfiles in a current-user-owned private mode-0700 directory, and set
`umask 077` before launching Docker so newly created cidfiles are private too.
Do not reserve them directly in shared `/tmp`, or pre-create the files that
Docker must create itself.
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
more than 2,048 entries, or files larger than 256 KiB fail closed. This is an
explicit registration channel; the guard does not search labels or enumerate
containers.

Dynamic registry mode requires `--stop-file PATH` and `--remove-containers`
together, plus an absolute real Docker executable. The marker must initially be absent.
Registry and stop-marker parent directories must exist before launch, belong to the
current user, and prohibit group/other writes. Existing registry files must have one
link, the current owner, and no group/other writes. Use a new private mode-0700
operator directory instead of placing these control files directly in shared `/tmp`. The guard
creates the stop marker with mode 0600 before terminating any owned process or cleaning up
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


### ScanEval OCI launch wrapper

`tools/codex_guard_docker.py` gates Docker create/start calls for the OCI backend.
Prepare a private mode-0600 configuration file in the operator directory:

```json
{
  "schema": 1,
  "real_docker": "/absolute/path/to/docker",
  "allowed_run_ids": ["run-explicitly-owned"],
  "registry_file": "/private/operator/run/containers.json",
  "stop_file": "/private/operator/run/guard.stop"
}
```

Put a task-local executable named `docker` first on the workload's PATH. Its
launcher sets `SCANEVAL_GUARD_DOCKER_CONFIG` to that absolute configuration path,
then execs an absolute Python 3.11+ interpreter with the absolute wrapper path and
its original arguments. Use proper shell quoting when constructing the launcher.
This assignment must happen in the launcher: ScanEval filters arbitrary variables
out of the Docker client's environment. Named model credentials still pass through
as required by the existing OCI backend; the wrapper does not print them.

The guard's `--docker` must name the real executable from the configuration,
**never the wrapper**. Pass the same registry and marker to the guard and enable
`--remove-containers`. The wrapper verifies `scaneval.backend=oci`, an exact
allowlisted `scaneval.run`, and role `worker`, `proxy`, or `probe`. It atomically
registers a newly created full container ID under a writer lock before returning
it. Starts require a registered ID and inspected ownership, recheck the stop
marker, then execute against the full ID to prevent name reuse from redirecting
work. If stop arrives during create, only that positively identified new container
is removed. Read, network and cleanup commands needed by the OCI backend remain
available; alternative launch commands such as `run` and `restart` are refused.

The append-only capacity is a budget of 2,048 containers **per guard invocation**,
including already-removed workers, proxies and probes. Plan invocations within that
budget; reaching it refuses the next creation without starting it. The registry
is not compacted during a run. A wrapper killed between creation and registration
can leave a stopped, unregistered container: it cannot be started through the gate
or spend quota, but cleanup of that artifact is not certified by the guard.

On exit it runs one bounded `docker container stop --time 0 -- <exact IDs>`
command for the registrations, including when the experiment command exits
normally, unless explicit removal was selected. It never discovers or prunes
containers. If the selected cleanup command fails, it inspects only the exact
registered IDs in one batched inspect and only their ID/running
fields. Every stdout JSON line and stderr missing-container diagnostic must map
to a registered ID exactly once; duplicate, foreign or unaccounted output fails
closed. Already removed containers count as `not_found` only when Docker
returns an exact missing-container error and a separate daemon-version read
succeeds. Connection errors, mismatched inspection IDs, and still-running
containers remain failures. Each control call has a five-second deadline,
with a shared ten-second cleanup budget plus bounded client-process cleanup.
The final receipt preserves every ID and its `stopped`, `removed`, `not_found`,
`still_running`, `not_removed`, or `unverified` state. `removed` means Docker
acknowledged forced removal, including an ID that was already absent; it does
not establish that every ID still existed when cleanup began. `not_found`
records the separate inspect-and-daemon proof after a cleanup-command failure.
An existing stopped
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
cleanup failure exits 125; SIGINT, SIGTERM, SIGHUP, and SIGQUIT request a controlled stop with exit
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
fresh successful request/response cycles and local age measured from the request
start, but cannot prove the upstream data is uncached. Equal consecutive
percentages are allowed. The
receipt explicitly reports `upstream_observation_time_available: false`.

A userspace monitor cannot enforce deadlines while suspended or after its own
SIGKILL, a host failure, or a blocked filesystem operation. Keep receipts and
cidfiles on responsive local storage. Resume detects elapsed reset/freshness
deadlines, but cannot undo work completed while the guard was unscheduled.

The automated regression suite uses fabricated endpoints and local synthetic
child processes. A separate harmless dedicated-engine Docker integration checks
actual missing-container diagnostics and shutdown; it calls no model:

```sh
python3 -m pytest tests/test_codex_quota_guard.py tests/test_codex_guard_docker.py tests/test_codex_quota_buckets.py -q
```

The [committed specification](designs/codex-quota-guard.md) records the scope
and acceptance requirements. Fresh Opus 5.5 code review is required before PR.
