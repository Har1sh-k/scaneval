# SB-TS-RW-074: Authenticated RCE via Custom MCP stdio server config (MCP/core.ts)

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-c9gw-hvqq-f33r`
- CVE: `CVE-2026-40933`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `b4665df8d1e727129d2b7fda615482e4701b3eb2` (release flowise@3.1.0)

## Vulnerability
The allowlist guards the executable name but the argument validators only look for shell metacharacters and file paths, so legitimate-looking flags that turn an allowlisted interpreter into an arbitrary code runner (npx -c, node -e/-p, python -c/-m) slip through. The validated serverParams are then handed to StdioClientTransport, which spawns the process with those argv.

## Source / Carrier / Sink
- Source: Authenticated user input: Custom MCP serverParams.command and serverParams.args from the canvas/REST API.
- Carrier: validateMCPServerConfig() accepts an allowlisted command plus args that pass the metacharacter/file-path checks, then those args reach StdioClientTransport.
- Sink: StdioClientTransport spawns serverParams.command with serverParams.args, executing arbitrary code (e.g. npx -c 'touch /tmp/pwn').
- Missing guard: No validation of command-specific code-execution flags (e.g. -c, -e, -m) for the allowlisted interpreters.

## Fix
Fix commit b4665df8 adds validateCommandFlags(command, args), enumerating dangerous flags per allowlisted command (npx: -c/--call/--shell-auto-fallback/-y; node: -e/--eval/-p/--print/...; python: -c/-m; docker: run/exec/-v/--privileged/...) and rejecting them in exact, =value, space-separated, and combined-short-flag forms. validateMCPServerConfig now calls validateCommandFlags after the existing arg checks, blocking npx -c style payloads.

## Scanner Expectation
Flag that user-supplied command/args reach a child-process spawn while validation (validateMCPServerConfig args block, lines 275-279) checks only metacharacters/paths and omits dangerous-flag enforcement, permitting OS command execution.
