# SB-RS-RW-006: Codex CLI exec() command injection in terminal chat

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `a3889f92e4ce5ee1f8d1bbe9bea8ba91a8997607`
- Fix commit: `63c99e7d8286f756d5bb41d8dd2856946ca41980`

## Scenario

The terminal chat UI integrates with the host desktop and uses child
processes to launch helper commands. Any shell-based process construction
in that layer is sensitive because it can mix untrusted chat content and
filesystem state into a shell command string.

## Vulnerability

The vulnerable code uses `exec()` with a formatted `osascript` command
string that interpolates `cwd` and a message preview directly into shell
syntax. If either field contains shell metacharacters, the host shell
interprets them as part of the command. That gives an attacker-controlled
working directory or message body a path to arbitrary code execution.

## Source / Carrier / Sink
- Source: untrusted `cwd` and chat-derived message preview
- Carrier: string interpolation into an `exec()` shell command
- Sink: shell execution via `exec()`
- Missing guard: avoid shell-string execution; pass structured argv to
  `spawn()`

## Annotated Region
- File: `codex-cli/src/components/chat/terminal-chat.tsx`
- Lines: 374-379
- Why this region is the scoring target: it contains the vulnerable
  `exec()` call where attacker-controlled values are embedded into a
  shell command string

## Scanner Expectation

A scanner should flag the `exec()` call because untrusted values flow
into a shell command string, creating a direct command injection sink.
