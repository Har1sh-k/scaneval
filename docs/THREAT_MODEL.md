# Threat model: what the isolation in this package is, and what it is not

ScanEval runs scanners it does not trust and records what they did. This document states
plainly what the code in `src/scaneval/execution.py` and `src/scaneval/materialize.py`
defends against and what it does not, so that nobody reads a passing bundle as more than it is.

It is referenced from the module docstrings of both files. If you change what those modules
defend, change this document in the same edit.

## The scanner is untrusted by design

A system under evaluation is an arbitrary program, often an agent driving a model, running with
the operator's own privileges on the operator's own machine. It reads a copy of a repository, it
writes files, it may run a subprocess, and in the interesting configurations it makes network
calls to a model provider. ScanEval never assumes any of that is well behaved. It assumes the
opposite and tries to record the truth about it.

Recording the truth is the property this package actually provides. An invocation ends with a
bundle whose `result.json` and `execution.json` are written together or not at all; a scan that
broke a contract is an explicit error record rather than an empty success; a path that left the
directory it belonged to is a refusal with a note rather than a file that was followed; a source
the scan changed is a `partial` result that cannot stand as a clean observation of the frozen
input. Those are claims about the record, and they hold against a buggy scanner and a confused
one.

## What the checks are for

Four mechanisms get mistaken for isolation. Each is worth having, and none of them is a boundary.

**Path containment.** `Containment` in `materialize.py` resolves a path whole and proves it is
still inside a directory whose own real path was captured before the scanner started. It catches
a symbolic link anywhere along a path, not only in the last component, and it catches a
directory the scanner replaced after the fact, because the base it compares against is not
resolved again afterwards. What it catches is a link that is there when the check runs.

**The input hash.** The exported tree is hashed before the scan and the result binds to that
hash, so a result cannot be attributed to an input nobody can reconstruct. It says what was on
disk when the hash was taken.

**Source-modification detection.** The same tree is walked again after the scanner returns, and
a difference is recorded as a changed execution condition. It compares two moments. It says
nothing about the moments in between.

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
  recorded in the execution record and is explicitly not enforced by this runner.

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
- Take the bundle out of the sandbox after the process has exited and the filesystem is no
  longer writable by anything the scan started, then hash it outside.

ScanEval does not provide any of this and does not pretend to. It declares the policy, records
the conditions, and refuses the escapes it can see. Directory separation documents the boundary;
it does not enforce it.

## How to read a bundle

- A clean bundle says the record is internally consistent and that no refused path, capture gap,
  source modification, or import loss was observed. It is not a certificate that the scanner
  behaved.
- A bundle from a run that was not OS-isolated carries the whole of this document as its caveat.
  Say so when you publish numbers from one.
- Treat the trace and the raw output as what the run reported about itself. `capture` says how
  completely each category was observed, and a category cannot claim complete observation in a
  bundle that holds no counted trace.
