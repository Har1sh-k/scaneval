# Threat model: what the isolation in this package is, and what it is not

ScanEval runs scanners it does not trust and records what they did. This document states
plainly what the code in `src/scaneval/execution.py` and `src/scaneval/materialize.py`
defends against and what it does not, so that nobody reads a passing bundle as more than it is,
and, for a system configured to run under it, what the `oci` execution backend in
`src/scaneval/isolation/` enforces and what it does not.

It is referenced from the module docstrings of those files. If you change what those modules
defend, change this document in the same edit.

## The scanner is untrusted by design

A system under evaluation is an arbitrary program, often an agent driving a model, running with
the operator's own privileges on the operator's own machine. It reads a copy of a repository, it
writes files, it may run a subprocess, and in the interesting configurations it makes network
calls to a model provider. ScanEval never assumes any of that is well behaved. It assumes the
opposite and tries to record the truth about it.

Recording the truth is the property this package actually provides. No failure this process can
observe leaves `result.json` in a bundle without `execution.json` beside it; a scan that broke a
contract is an explicit error record rather than an empty success; a path that left the directory
it belonged to is a refusal with a note rather than a file that was followed; a source the scan
changed is a `partial` result that cannot stand as a clean observation of the frozen input. Those
are claims about the record, and they hold against a buggy scanner and a confused one.

**The exception to the first of those, stated rather than glossed.** "Written together or not at
all" is what `_write_new_documents` aims at and not what it can guarantee. Both documents are
serialized, encoded, and staged as temporary files before either is renamed into place, and a
rename that fails removes the one that already landed, so every failure the process sees is
contained. Two failures are outside that. The two renames are separate system calls, so a process
killed between them, by a `SIGKILL`, an out-of-memory kill, or a power loss, leaves `result.json`
alone in the bundle. And the removal that undoes the first rename can itself fail, on a read-only
filesystem or a directory whose permissions changed under the run; the invocation then raises
that failure and `result.json` stays. Both leave a successful-looking result with no record of
the run that produced it.
`tests/test_v2_execution.py::test_a_rollback_removal_that_fails_leaves_the_result_without_its_execution_record`
drives the second and asserts the split bundle. The first cannot be driven from inside the
process doing the renaming. Reading a bundle means checking that both documents are there, not
assuming it.

A third shape is not an exception to it, because it leaves neither document: several failures end
an invocation with a bundle directory holding `request.json`, `raw/`, and `trace/` and nothing
else. An adapter whose `name` or `adapter_version` is not a non-empty string is one, and the
unbounded read named under the limits below is another.

## What the checks are for

Four mechanisms get mistaken for isolation. Each is worth having, and none of them is a boundary.

**Path containment.** `Containment` in `materialize.py` resolves a path whole and proves it is
still inside a directory whose own real path was captured before the scanner started. It catches
a symbolic link anywhere along a path, not only in the last component, and it catches a
directory the scanner replaced after the fact, because the base it compares against is not
resolved again afterwards. What it catches is a link that is there when the check runs.

**The input hash.** The exported tree is hashed before the scan and the result binds to that
hash, so a result cannot be attributed to an input nobody can reconstruct. It says what was on
disk when the hash was taken, and it says it about the content of regular files, which is the
same enumeration and the same structural limit as the check below.

**Source-modification detection.** The same tree is walked again after the scanner returns, and
a difference is recorded as a changed execution condition. It compares two moments. It says
nothing about the moments in between, and it says nothing at all about most of what a directory
can hold.

The second gap there is structural rather than temporal, and it is easy to miss because the
first one is the one everybody names. Both walks are `walk_regular_files`, which enumerates
regular files and hashes their contents: a symbolic link, a named pipe, a socket, a device node,
and a directory with nothing in it are not in the map, on either side, and neither are a file's
mode, owner, timestamps, or extended attributes. So a scanner can plant a symbolic link in the
exported source pointing at the operator's private key, plant a named pipe where the next tool
to read the tree will block on it, create an empty directory, or make a file executable, and the
comparison is between two identical maps. `source_modified` reads `false`, `modified_paths` is
empty, and the run is a clean `success`. No race is involved and no timing helps: the check
cannot see these things at any moment, so waiting for a quieter one changes nothing.

What it does catch is content. A regular file whose bytes changed, a regular file that appeared,
a regular file that went away, and a regular file replaced by something that is not one all move
the map and are recorded. An extra hard link the scanner makes to a file already in the tree is
caught too, because the new name is a regular file the walk enumerates. Read `source_modified:
false` as "no regular file's content or name in this tree changed between the two walks", which
is what it is, and never as "the input the scanner was handed is the input that is there now".

`tests/test_v2_execution.py::test_a_scanner_that_changes_the_input_in_ways_the_walk_cannot_see_is_recorded_as_a_clean_run`
plants all four, asserts the clean bundle the code really produces, and carries the hard link
beside them as the control. It documents the gap rather than pretending to close it, for the same
reason the restore-before-return test does.

**State capture.** The scanner's scratch directories are copied into the bundle without
following a symbolic link, and a file the staged tree would have carried in under a second name
is copied so the bundle holds its own inode. It preserves what is there at the end.

Together they defend against a careless or buggy scanner and against accidental escape: a tool
that writes outside its workspace by mistake, a harness that leaves a link pointing at the
operator's home directory, a scan that edits the tree it was given and would otherwise have been
recorded as a clean observation of a tree that no longer exists. They do not defend against a
scanner that is trying to deceive the record.

## The limit, and the worked example

**A scanner running concurrently in a directory it controls can defeat any check made before or
after it runs.** Every check above happens either before the scanner process starts or after it
returns. The scanner owns the workspace in between. This is a time-of-check to time-of-use race,
and the attacker picks the width of the window.

The worked example is the restore-before-return race. A scanner is handed an exported source
tree. It rewrites a file in that tree, scans the version it wrote, writes the original bytes
back, and returns. The before-hash and the after-hash are taken on either side of all of that
and they match. The bundle records `source_modified: false`, a `success` status, and an
`input_hash` that binds the result to a tree the scanner did not scan. Nothing in the record is
wrong about what it observed. What it observed simply does not cover what happened.

`tests/test_v2_execution.py::test_a_scanner_that_restores_the_source_before_returning_is_recorded_as_a_clean_run`
drives exactly that and asserts the clean-looking bundle the code really produces. It documents
the gap rather than pretending to close it, because a test that claimed to close it would be
worse than no test at all.

The same shape has other instances, and listing them is not a to-do list, because none of them
can be closed from inside this process:

- A file replaced between the containment check and the read that follows it. Resolving a path
  is not opening it.
- A hard link planted, hashed, and then repointed. De-aliasing happens when the staged tree
  enters the bundle; a scanner that is still running can act after that moment.
- A scanner that leaves a background process alive after its own exit, which then edits the
  workspace while the runner is walking it.
- Bytes read out of the workspace and sent anywhere the process can reach. Network policy is
  recorded in the execution record and is explicitly not enforced by the local backend; the
  `oci` backend described below enforces it for the systems that run under it.

Patching individual instances of this class would misrepresent what the package defends. It
would also be endless: each patch narrows a window that the attacker chooses the width of.

## The class, named: deciding a path and using it are two operations

Those instances are one defect wearing different clothes, and the shape is worth naming exactly,
because it is what keeps coming back in review as if it were a new bug each time:

**ScanEval decides what a path is at one moment and acts on that path at another, and the
scanner owns the directory in between.** Resolving a path, listing a directory, stating an entry,
creating a parent directory, and hashing a file are each a separate operation from the open that
follows it. Whatever the scanner puts at that path in the gap is what gets opened. No check
inside this process closes the gap, because the check is one of the two operations that make it.
A check can refuse what was planted before it ran. It can say nothing about what is planted
after.

Two worked examples, both in `stage_record` in `src/scaneval/adapters/llm_harness.py`, which
copies a harness record into this run's raw output at a path the harness itself can write to:

- **A named pipe planted where a record is staged.** The staging path is checked against the
  enclosure, then opened for writing. A harness that creates a FIFO at that path in between is
  not trying to read or write anything through it; it is handing the invocation an open that
  never returns. Without `O_NONBLOCK` that open blocks until a reader appears, and nothing ever
  reads it, so the invocation hangs with no bundle, no execution record, and no evidence that the
  run happened at all. It is the write-side twin of the pipe that used to block the record read.
- **A destination hard-linked to a host file.** The same open carries `O_NOFOLLOW`, which refuses
  a symbolic link as the last component. A hard link is not a symbolic link: it is a second
  directory entry for the same inode, `O_NOFOLLOW` has nothing to refuse, and the open truncates
  and overwrites the host file the harness linked there. The scanner does not read anything it
  could not already read; it gets ScanEval to write, with the operator's privileges, into a file
  of its choosing.

They sit beside the restore-before-return race above. That one is a gap between two of ScanEval's
own reads; these two are gaps between a decision about a path and the use of it. Same class,
different window, and the scanner picks the width of each.

`tests/test_v2_llm_harness.py::test_a_named_pipe_where_a_record_is_staged_does_not_block_the_invocation`
and `::test_a_staging_destination_hard_linked_to_a_host_file_is_not_overwritten` drive both
examples, and
`tests/test_v2_execution.py::test_the_threat_model_document_names_the_class_two_reported_findings_belong_to`
fails if this section stops naming the class, the examples, or the limit of the hardening.

**What has been hardened here, and what that is worth.** `stage_record` now opens its destination
with `O_NONBLOCK` and proves with `fstat`, on the descriptor it just opened, that the destination
is a regular file carrying exactly one link, before it truncates anything or writes a byte. That
refuses both instances above. It is cheap defence in depth and worth having, in the same way
`read_regular_file` is worth having on the read side. It does not close the class and must never
be read as closing it: the enclosure check and the open are still two operations, the `mkdir` and
the open are still two operations, and a harness process still alive can plant a pipe, a link, or
a whole substituted directory between any two of them. The same is true of the de-alias sweep in
`execution.py`, which now records every staged entry it could not inspect instead of skipping it:
that makes a failed observation visible, which is this package's actual job, and it still reads
the tree at one moment rather than owning it.

**What OS-level isolation gives that no check here can.** The hardenings narrow windows. An
operating system removes the scanner's ability to act inside them at all, which is a different
kind of thing and the only kind that closes this:

- A read-only mount makes the bytes unable to change between the hash and the read. No in-process
  check can establish that, because it can only look again and compare two moments.
- A container or virtual machine created for one invocation and destroyed after it means no
  process survives to act in any gap. In-process, a background process the scanner left behind is
  invisible and unbounded.
- A filesystem frozen before the bundle is taken out means every path ScanEval resolved is still
  the path it opens. Inside the process, that is exactly what cannot be established.
- An unprivileged user with no path to the operator's files means a write ScanEval is tricked
  into making lands somewhere that does not matter. The hard-link example above is dangerous only
  because ScanEval runs with reach the scanner should never have.

## The second limit, named: nothing here bounds what a scanner can make ScanEval read, copy, or spend

The first limit is about *when* a check runs. This one is about *how much* the checks themselves
cost, and it is separate because no amount of ordering fixes it:

**Every size in this package is the scanner's to choose. ScanEval sets no ceiling on the bytes it
reads into memory, the bytes it copies into the bundle, or the seconds it spends doing either.**

The invocation timeout bounds the scanner's own process, and only to the extent the adapter
enforces it; it bounds nothing the runner does after the scanner returns, and that is where the
reading and copying happen. Four places, all reached with input the scanner wrote:

- **The trace count.** `_read_trace` calls `read_regular_file` on the declared trace file, which
  reads the whole file into memory in one call, and then decodes it as UTF-8. There is no size
  check anywhere on that path. A scanner that writes a trace larger than the memory the process
  can get raises `MemoryError`, which is neither the `OSError` nor the `UnicodeDecodeError` that
  call site contains, so it travels out of `run_invocation` uncaught. The invocation then ends
  with a bundle directory holding `request.json`, `raw/`, and `trace/`, and neither `result.json`
  nor `execution.json`: one file the scanner chose the size of, and no record of the run at all.
  The harness adapter's `read_record` reads every harness record the same unbounded way, and
  contains `OSError` alone for the same reason.
  `tests/test_v2_execution.py::test_a_failure_the_trace_read_does_not_contain_ends_the_invocation_with_no_documents`
  injects the failure rather than provoking it, and asserts the bundle that is left.
- **The state capture.** Each directory the adapter declares as scanner scratch space is copied
  whole into `raw/harness-state/`. The scanner writes that directory and decides how large it is.
- **The de-alias sweep.** Every staged file with a link count above one is copied to give the
  bundle its own inode. The scanner decides how many such files there are and how large each is.
- **The artifact hashes.** `sha256_file` streams, so memory is bounded there, but the time and
  the disk reads are not.

Two smaller shapes belong with them. A note that names every staged entry the sweep could not
clear joins all of them into one string, so an execution record can be made large by making many
unclearable entries. And the exported source is walked and hashed twice, before and after, over
whatever the scanner left in it.

None of this is a deception of the record; it is a denial of service against the run, and in the
trace-read case a denial of the record itself. It is not patchable into safety from in here
either: a cap on the trace read turns a crash into a refusal, which is better, but the copies and
the walks would each need their own cap, each cap is a number somebody has to pick, and a scanner
that wants to exhaust the host has the whole filesystem to do it with. What actually bounds it is
the environment: a memory limit, a disk quota, and a wall-clock kill on the sandbox, which is the
same answer as the section above and for the same reason.

## What closes it, and what an operator should do

Closing this requires taking control of the filesystem and the process away from the scanner,
which is an operating-system job:

- Run each invocation inside a **container or a virtual machine** that is created for that
  invocation and destroyed after it. A virtual machine is the stronger of the two and is the
  right choice when the scanner runs model-generated code.
- Mount the exported input **read-only** inside it, so restoring bytes is not something the
  scanner can do because writing them was not. Give the scanner a separate writable scratch
  mount for its own output.
- Deny the network, or allow exactly the model provider endpoint the run declares, at the
  network namespace or firewall rather than by asking the scanner nicely. `network_policy` in
  the execution record is a declaration; the environment has to enforce it.
- Run as an unprivileged user with no access to the operator's home directory, credentials, or
  the ScanEval run directory. Nothing in the bundle path should be reachable from inside.
- Give the sandbox a **memory limit, a disk quota, and a wall-clock kill**, and size them for the
  runner's own post-scan reading and copying rather than for the scanner alone. Nothing in this
  package bounds any of the three; the section above says where each is spent.
- Take the bundle out of the sandbox after the process has exited and the filesystem is no
  longer writable by anything the scan started, then hash it outside.

The local backend provides none of this and does not pretend to. It declares the policy, records
the conditions, and refuses the escapes it can see. Directory separation documents the boundary;
it does not enforce it. The `oci` backend, next, provides most of this list for the scanners that
can use it, and states what it leaves out.

## The `oci` backend: what it enforces, and what it does not

A system whose 2.1 run configuration carries `"execution": {"backend": "oci", "image":
"<name>@sha256:<digest>"}` runs every scanner process in a Docker container of its own
(`src/scaneval/isolation/`). Only an adapter that declares `oci_compatible` may: every process it
starts goes through `run_command`, its scanner exists in a Linux image, and every host-side read of
what a command wrote is one that does not follow a link. Today that is `semgrep`. `llm-harness`
and `deepsec` are refused, with the reason recorded as the system's skip reason, because their
tools are host installs with no Linux image and not every process they start is known to go
through the backend. A system configured for `oci` is never run locally in its place, and a policy
the backend cannot implement is a recorded refusal of the invocation, never a weaker policy.

**What it enforces, for each scanner process.** `tests/test_v2_isolation_docker.py` checks each of
these against a real engine; they were measured on Docker 29 under Colima.

- **A container for that one command, removed after it.** `docker create` under a unique name and
  this run's labels, then `docker start --attach` under the command's timeout. On a timeout or any
  error the container is killed by name, inspected for its exit code and `OOMKilled`, and only then
  removed; killing the docker client does not stop a container, so nothing relies on that. A
  timed-out scan that left background, `setsid`, `nohup`, and double-forked children behind leaves
  no process and no container. A container that exits 0 while recording an out-of-memory kill is a
  failed command, not a clean one, and a container the engine could not start is recorded as never
  started, so nothing is recorded as enforced over a process that did not run.
- **The process settings.** A read-only root filesystem, every capability dropped,
  `no-new-privileges`, a non-root user (65534:65534 unless configured; uid 0 is refused), no IPC
  namespace, an init process, pids, memory with swap equal to it, CPU, core-dump, and open-file
  limits, and a size-limited `noexec` tmpfs at `/tmp` that is also `HOME`. The tmpfs counts against
  the memory limit. The image is pinned by digest, never pulled, and recorded by id and repository
  digests.
- **Only these mounts**, each at its own path and each with `--mount`, never `-v`, which turns a
  source the daemon cannot see into a silently empty directory: the workspace copy of the source
  read-only; the adapter's declared state directories inside it, writable; the staged raw output
  and trace, writable; and the adapter's declared runtime paths read-only, each strictly inside the
  source cache and holding no socket, since `connect()` works through a read-only mount. Never the
  operator's home, the source cache as a whole, the run directory that holds `evaluator/pack.json`,
  the Docker socket, or a directory above any of them. A hostile fixture scanner cannot read a
  host-only sentinel or the run's labels, and cannot write the source, the root filesystem, or
  anything unmounted.
- **Only these variables:** `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, `TERM`, the proxy variables, and the
  declared credentials, each passed by name so its value reaches the container through the docker
  client's own environment and never appears on a command line or in a record. The record's
  `environment.passthrough` lists the names the backend recorded in
  `isolation.settings.environment` (what it set, and the credentials it passed), and nothing of the
  operator's environment that was dropped.
- **The network policy.** `none` is no interface but loopback. `model_provider_only` is an internal
  network made for the invocation with `gateway_mode_ipv4=isolated`, refused unless inspection shows
  no gateway (the engine accepts an option it does not apply), and a dual-homed egress proxy that
  forwards `CONNECT` only to the declared host and port pairs and logs every decision; the allow and
  deny counts are read back into the record. Under both, external addresses, external DNS, the
  engine's host and its gateway, `169.254.169.254`, and IPv6 are unreachable. `unrestricted` is a
  plain bridge network and is recorded with `enforced: false`; under Colima or Docker Desktop it
  also reaches services bound to the host's own loopback.
- **A preflight before any scanner process:** the engine answers, the image is present, every mount
  source is visible to the daemon (an invisible one is a recorded refusal, never an empty scan), and
  the networks are created and inspected.

**What that changes in the limits above.** With the source mounted read-only, the scanner cannot
restore bytes before it returns, because it could never write them. Each command's container is
removed before that command returns, so no scanner process is alive while ScanEval reads, hashes,
moves, or copies what the scan left: the windows in the class named above still exist, but nothing
of the scanner's is left running to act in them. The in-process checks all still run and are now
defence in depth.

**What it does not change, and what it trusts.**

- Everything the scanner writes is still untrusted. It can leave links, pipes, and files of any
  size under the raw output, the trace, and its state directories, and they reach the same sweep and
  the same reads as a local run's. Two reads happen before that sweep and are held to the same rule:
  an `oci_compatible` adapter reads what its commands wrote without following a link, and the backend
  opens each command's output without following a link or a redirected directory that an earlier
  container of the same scan left there, so a container cannot make the host write into, or quote,
  a file it chose.
- Nothing bounds a writable bind mount: the engine applies no quota to one (`--storage-opt` is
  ignored), so raw output is bounded by the host disk alone, and the second limit above is unchanged
  for everything ScanEval does after the scan.
- The engine, its kernel, and the image are trusted rather than verified, beyond the image's digest.
  On a rootful engine without user namespaces, uid 0 in a container is root on the engine's host; the
  backend never runs a scanner as uid 0, but a kernel escape is outside what it defends. The seccomp
  and AppArmor profiles are the engine's defaults, recorded as found.
- The preflight proves that the daemon can see each mount source, not that what it sees is the
  host's directory. An engine inside a virtual machine that holds a directory of its own at the same
  path mounts that one. Under Colima a directory removed and re-created under the shared home stays
  invisible to the daemon for about a second, and a scan in that window is refused.
- A declared credential's value is in the container's configuration while the container exists,
  visible to anyone who can inspect containers on that engine. The proxy does not look inside TLS, so
  a declared endpoint receives whatever the scanner sends it, including anything it read from its
  workspace.
- A ScanEval process that is itself killed leaves its containers and networks on the engine. They
  carry the label `scaneval.backend=oci` and the run id, so `docker ps --all --filter
  label=scaneval.backend=oci` finds them.

## How to read a bundle

- Check that both `result.json` and `execution.json` are there before reading either. A bundle
  holding one without the other is a killed or failed write, not a result: the exception named at
  the top of this document. A bundle `scaneval import sarif` wrote is not a run: nothing executed,
  and its `import.json` stands where `execution.json` would ([SARIF import](SARIF_IMPORT.md)).
- A clean bundle says the record is internally consistent and that no refused path, capture gap,
  source modification, or import loss was observed. It is not a certificate that the scanner
  behaved.
- `source_modified: false` covers the content and the names of regular files, and nothing else. A
  link, a pipe, a device node, an empty directory, or a mode change the scanner left in the input
  is not in that comparison at all.
- A bundle from a run that was not OS-isolated carries the whole of this document as its caveat.
  Say so when you publish numbers from one.
- An `oci` bundle's execution record is 2.1 and says what bounded the run in `isolation`:
  `enforced` is true only when a scanner container actually ran under the recorded settings, and
  `network_policy.enforced` only when, in addition, the policy was `none` or `model_provider_only`.
  `isolation.containers` gives each container's exit code, `oom_killed`, `timed_out`, and whether it
  was removed; `isolation.mounts` lists every mount with the home directory spelled `~`. A refusal
  reads `enforced: false` with the reason in `isolation.note`.
- Treat the trace and the raw output as what the run reported about itself. `capture` says how
  completely each category was observed, and no category can claim it was observed at all, to any
  extent, in a bundle that holds no counted trace: `complete`, `partial` and `redacted` are each
  rewritten to `unavailable` there. `not_applicable` is untouched, because it says the category
  does not apply to this scan rather than that this run saw something.
