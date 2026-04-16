# SB-RS-RW-007: Codex CLI basename-based trust escalation for local binaries

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `aabe0f259caf3e0ce297f2d3a6b1372d7088dc83`
- Fix commit: `78f87987dfce8737cd99714b0af36a990c69e304`

## Scenario

Codex uses exec policy rules to decide whether known commands like `git`
can run with reduced friction. That policy is safe only if the command
identity being checked matches the actual binary that will execute.

## Vulnerability

`evaluate_exec_policy()` performs trust lookup using the basename of the
command path. A repo-local executable such as `./git` is therefore
evaluated as `git` and can inherit the trust policy intended for the
system binary `/usr/bin/git`. A malicious local binary can then be
auto-approved and run with privileges intended only for the trusted
system command.

## Source / Carrier / Sink
- Source: repo-local executable path chosen by the model or repository
- Carrier: basename-only policy lookup in exec-server policy evaluation
- Sink: trusted execution of a local binary under elevated approval rules
- Missing guard: distinguish local paths from globally trusted binaries

## Annotated Region
- File: `codex-rs/exec-server/src/posix.rs`
- Lines: 176-210
- Why this region is the scoring target: it contains the command identity
  evaluation logic where basename matching can confuse a local binary
  with a trusted system binary

## Scanner Expectation

A scanner should flag the basename-based trust decision because policy
derived from `git` should not automatically apply to `./git` or other
workspace-local executables.
