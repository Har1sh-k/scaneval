# SB-RS-RW-008: Codex CLI git global options bypass safe-command allowlist

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `e36ebaa3daca0e5e73dc2d2af82b04c9eca2526b`
- Fix commit: `af0427377898290356e47b9b3a3311083d9ed3fb`

## Scenario

Codex has a safe-command path for read-only git operations. That path is
only safe if dangerous global options are rejected before the command is
auto-approved.

## Vulnerability

The vulnerable allowlist checks git subcommands but ignores dangerous
global options that can appear before the subcommand, such as:

- `--exec-path`
- `--git-dir`
- `--work-tree`
- `--namespace`
- `--super-prefix`

Those options can redirect helper lookup, repository resolution, or
config loading to attacker-controlled paths. A command that looks like a
benign read-only git invocation can therefore still trigger arbitrary
code execution.

## Source / Carrier / Sink
- Source: model-generated git command with global options
- Carrier: safe-command validation that checks only the command family or
  subcommand
- Sink: auto-approved git execution using attacker-controlled helper or
  config paths
- Missing guard: reject unsafe global git options before allowlisting

## Annotated Region
- File: `codex-rs/shell-command/src/command_safety/is_safe_command.rs`
- Lines: 136-165
- Why this region is the scoring target: it contains the git safety logic
  that misses dangerous global options appearing before the subcommand

## Scanner Expectation

A scanner should flag the git allowlist logic because global options can
turn an otherwise safe-looking git command into an arbitrary code
execution vector.
