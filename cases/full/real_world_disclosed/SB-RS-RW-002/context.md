# SB-RS-RW-002: Codex CLI auto-approves ripgrep with dangerous flags

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: `CVE-2025-54558`
- Vulnerable commit: `18b2b30841aaba88d6e37ef6cdde57e99f8d6564`
- Fix commit: `6cf4b96f9dbbef8a94acc1ff703eb118481514d8`

## Scenario

Codex CLI has a command allowlist that decides whether a generated shell
command can run without interactive approval. `rg` (ripgrep) is treated
as a trusted read-only utility in many workflows, so it sits on the
auto-approved path.

## Vulnerability

`is_safe_to_call_with_exec()` treats `rg` as safe based only on the
command name. It does not inspect dangerous flags that turn ripgrep into
an execution primitive:

- `--pre` executes an arbitrary helper command for each file
- `--hostname-bin` invokes an external hostname helper
- `--search-zip` / `-z` can trigger external decompression helpers

That means a model-generated command such as `rg --pre=payload pattern .`
can be auto-approved even though it executes attacker-controlled code.

## Source / Carrier / Sink
- Source: model-generated shell command
- Carrier: safe-command classification in `is_safe_to_call_with_exec()`
- Sink: trusted exec path that skips user approval for commands labeled
  safe
- Missing guard: flag-level validation for `rg`

## Annotated Region
- File: `codex-rs/core/src/is_safe_command.rs`
- Lines: 22-28
- Why this region is the scoring target: it contains the allowlist branch
  that recognizes `rg` as safe without checking for execution-capable
  flags

## Scanner Expectation

A scanner should flag the `rg` allowlist entry because the command name
alone is insufficient to prove safety when specific flags introduce
arbitrary command execution.
