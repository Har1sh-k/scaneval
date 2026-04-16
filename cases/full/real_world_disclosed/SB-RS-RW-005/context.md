# SB-RS-RW-005: Codex CLI apply_patch sandbox bypass via symlinks

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `301ec72107f107ac5c6103660e276a25bc18273e`
- Fix commit: `221ebfcccc3ddd957d5903b8c09e4d02e62387e7`

## Scenario

Codex exposes an `apply_patch` path to edit files in the workspace. That
path is expected to respect the same writable-root restrictions as other
filesystem operations.

## Vulnerability

The vulnerable `apply_patch` implementation runs patch operations
in-process and does not route them through the sandbox. It also does not
reject symlinks or hardlinks that point outside the writable root. A
model-generated patch can therefore create or follow a link that escapes
the workspace boundary and write arbitrary files outside the intended
sandbox.

## Source / Carrier / Sink
- Source: model-generated patch content and target file path
- Carrier: in-process `apply_patch` logic
- Sink: host filesystem writes that bypass workspace root enforcement
- Missing guard: sandbox mediation and symlink / hardlink containment

## Annotated Region
- File: `codex-rs/core/src/apply_patch.rs`
- Lines: 21-40
- Why this region is the scoring target: it covers the in-process patch
  handling entry path that operated outside the sandbox boundary

## Scanner Expectation

A scanner should flag `apply_patch` as a filesystem escape because a
write primitive that bypasses sandbox mediation and link checks can write
outside the intended workspace root.
