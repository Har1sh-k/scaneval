# SB-RS-RW-010: Codex CLI tilde expansion allows absolute-path escape

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `3355adad1d80dc4a45db727469f9cceb3aa63290`
- Fix commit: `8179312ff5b39ea879bceb7eaed8187002a5fa04`

## Scenario

Codex uses path utilities to normalize configuration and sandbox roots.
Those helpers are security-sensitive because small path parsing mistakes
can expand writable roots outside the intended workspace.

## Vulnerability

`maybe_expand_home_directory()` handles `~` and `~/` but leaves `~//`
untouched. When that value is later joined with another path, the
right-hand side begins with `/`, so `Path::join` discards the left-hand
base and resolves the result as an absolute path. A config value like
`~//etc` therefore becomes `/etc`, broadening a writable root to an
arbitrary system directory.

## Source / Carrier / Sink
- Source: config-controlled path string containing `~//`
- Carrier: incomplete tilde expansion in path normalization
- Sink: absolute path resolution that escapes the intended root
- Missing guard: reject or correctly normalize double-slash tilde forms

## Annotated Region
- File: `codex-rs/utils/absolute-path/src/lib.rs`
- Lines: 25-40
- Why this region is the scoring target: it contains the home-directory
  expansion helper whose incorrect handling of `~//` enables absolute
  path escape

## Scanner Expectation

A scanner should flag the path-normalization logic because `~//` is
treated as a home-relative path but resolves as an absolute path, which
can widen sandbox writable roots outside the workspace.
