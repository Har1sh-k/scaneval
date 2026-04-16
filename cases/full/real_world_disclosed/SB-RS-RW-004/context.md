# SB-RS-RW-004: Codex CLI untrusted project config.toml loading

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: none published
- Vulnerable commit: `3a9f436ce00124cabe71f102c3a2c29f097ccc4c`
- Fix commit: `7351c129992d85405e53a285cb4916ccb223489f`

## Scenario

Codex CLI supports local project configuration, including MCP servers and
skills that can launch code or enable powerful capabilities. Those
settings are only safe if the project directory is already trusted by the
user.

## Vulnerability

The config loader walks `config.toml` from the current working directory
and parent directories without first proving the directory is trusted. A
malicious repository can commit `.codex/config.toml` with MCP server or
skill definitions that execute arbitrary code when a developer runs
Codex inside that repository.

## Source / Carrier / Sink
- Source: attacker-controlled project `.codex/config.toml`
- Carrier: config loader directory walk from CWD and parent directories
- Sink: trusted config application, including MCP servers and skills
- Missing guard: trust check before loading project-local configuration

## Annotated Region
- File: `codex-rs/core/src/config_loader/mod.rs`
- Lines: 80-167
- Why this region is the scoring target: it contains the directory walk
  and project-layer loading behavior that imports local config before a
  trust decision

## Scanner Expectation

A scanner should flag the project config loading path because it treats
repository-controlled configuration as trusted startup input and can lead
to command execution through MCP or skill activation.
