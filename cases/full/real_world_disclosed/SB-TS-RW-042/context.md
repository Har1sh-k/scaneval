# SB-TS-RW-042: Workspace dotenv blocklist omits connector endpoint host variables, allowing endpoint redirection

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-55cf-xx38-4p9p`
- CVE: `CVE-2026-45003`
- Vulnerable commit: `f788c88b4c508c335336fb292afed8c900656d6d` (release v2026.4.21)
- Fix commit: `0623079e98abf7202591f1b04a89755eb7ec9272` (release v2026.4.22)

## Vulnerability
Workspace .env is an untrusted surface but the blocklist was incomplete: connector endpoint host variables were neither in the explicit blocked-key set nor matched by the two existing suffixes, so they fell through to be applied to the process environment. With the endpoint host attacker-controlled, connector clients (Matrix/Mattermost/IRC/Synology) would send credentialed traffic to an arbitrary destination.

## Source / Carrier / Sink
- Source: An untrusted workspace .env file (attacker-controlled repository/workspace) read by the dotenv loader.
- Carrier: shouldBlockWorkspaceRuntimeDotEnvKey / BLOCKED_WORKSPACE_DOTENV_SUFFIXES filtering, which decides whether a workspace env var is applied to process.env.
- Sink: Connector endpoint resolution (Matrix homeserver, Mattermost/Synology base URL, IRC host) that reads the now-attacker-set env var and issues outbound network requests to it.
- Missing guard: The endpoint host env vars (and the _HOMESERVER suffix) are absent from the workspace dotenv blocklist, so the untrusted value is not stripped before connector use.

## Fix
The fix adds the specific connector endpoint keys (IRC_HOST, MATTERMOST_URL, MATRIX_HOMESERVER, SYNOLOGY_CHAT_INCOMING_URL, SYNOLOGY_NAS_HOST) to BLOCKED_WORKSPACE_DOTENV_KEYS and adds the _HOMESERVER suffix to BLOCKED_WORKSPACE_DOTENV_SUFFIXES so per-account Matrix homeserver overrides and generic API-host/base-url style overrides from workspace .env are all blocked, while trusted global runtime dotenv loading remains separate.

## Scanner Expectation
Flag that an externally controlled configuration value (workspace .env) flows into a network endpoint host without being constrained to a trusted set, enabling outbound request redirection (server-side request forgery / externally controlled resource reference).
