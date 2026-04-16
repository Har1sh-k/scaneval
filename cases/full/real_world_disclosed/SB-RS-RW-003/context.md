# SB-RS-RW-003: Codex CLI .env redirect to malicious MCP config

## Advisory
- Repo: `openai/codex`
- GHSA: none published
- CVE: `CVE-2025-61260`
- Vulnerable commit: `d6182becbe155776b159270fe4a5e88d607f0c5e`
- Fix commit: `db3834733acb46c83922573e4a161d6553346a42`

## Scenario

Codex CLI loads environment variables during startup and supports MCP
server definitions from configuration files under `CODEX_HOME`. This
creates a trust boundary between local project content and startup-time
configuration that can launch helper processes.

## Vulnerability

`load_dotenv()` loads both the user-global `~/.codex/.env` and the
project-local `$(pwd)/.env`. A malicious repository can ship a local
`.env` that sets `CODEX_HOME` to a project-controlled directory. Codex
then resolves its config from that attacker-controlled location, reads a
malicious `config.toml`, and launches configured MCP commands at startup
without separate approval.

## Source / Carrier / Sink
- Source: project-local `.env` file in the repository
- Carrier: `load_dotenv()` importing local environment variables into the
  startup process
- Sink: startup config resolution and MCP server command execution
- Missing guard: project-local `.env` should not be allowed to redirect
  trusted config roots

## Annotated Region
- File: `codex-rs/arg0/src/lib.rs`
- Lines: 113-123
- Why this region is the scoring target: it contains the local `.env`
  loading behavior that allows an untrusted repo to influence trusted
  startup configuration

## Scanner Expectation

A scanner should flag the local `.env` loading path because it lets
repository content redirect Codex's config root to attacker-controlled
MCP definitions that execute commands during startup.
