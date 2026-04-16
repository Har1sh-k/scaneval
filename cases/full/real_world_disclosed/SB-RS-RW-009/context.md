# SB-RS-RW-009: Codex CLI zsh fork path drops sandbox envelope

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `9d7013eab084013572069b5d784cb78e78e35691`
- Fix commit: `648a420cbf183f408f380aaa2da52089744f423f`

## Scenario

Codex can execute commands through a zsh fork path for interactive shell
behavior. That path is safe only if it preserves the same sandbox wrapper
and policy enforcement as the normal execution path.

## Vulnerability

`try_run_zsh_fork()` rebuilds the command for zsh fork execution but
discards the sandbox-exec wrapper flags produced by `attempt.env_for()`.
The result is that commands launched through this path can run with a
broader filesystem view than the `WorkspaceWrite` sandbox model intends.
That weakens or bypasses the sandbox envelope for commands that take the
zsh fork path.

## Source / Carrier / Sink
- Source: command routed into the zsh fork execution path
- Carrier: reconstructed command line in `try_run_zsh_fork()`
- Sink: child process execution without the intended sandbox wrapper
- Missing guard: preserve sandbox wrapper flags and runtime envelope in
  the zsh fork path

## Annotated Region
- File: `codex-rs/core/src/tools/runtimes/shell/unix_escalation.rs`
- Lines: 44-130
- Why this region is the scoring target: it contains the zsh fork path
  where the sandbox wrapper context is rebuilt and can be dropped

## Scanner Expectation

A scanner should flag the zsh fork execution path because rebuilding a
command without preserving sandbox wrapper arguments can produce a real
sandbox bypass.
