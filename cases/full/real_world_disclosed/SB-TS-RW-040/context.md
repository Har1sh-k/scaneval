# SB-TS-RW-040: Workspace dotenv blocklist omits MINIMAX_API_HOST, allowing host override of credentialed MiniMax requests

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-h2vw-ph2c-jvwf`
- CVE: `CVE-2026-44992`
- Vulnerable commit: `041266a6699cac3baef8ef39db41fa26f29f9db3` (release v2026.4.15)
- Fix commit: `2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1` (release v2026.4.20)

## Vulnerability
Workspace .env values are untrusted but the endpoint-redirection blocklist only covered the _BASE_URL suffix and a fixed key set, neither of which captured MINIMAX_API_HOST. The MiniMax request path then used that env-supplied host to build the API origin, so an attacker-controlled workspace could repoint credentialed requests off-host.

## Source / Carrier / Sink
- Source: A MINIMAX_API_HOST value set in an attacker-controlled workspace .env file.
- Carrier: The workspace-dotenv blocklist in src/infra/dotenv.ts fails to filter MINIMAX_API_HOST, so it is injected into process env and read by coerceApiHost() in src/agents/minimax-vlm.ts to build the request origin.
- Sink: The credentialed MiniMax HTTP request is sent to the env-supplied origin with the MiniMax API key in the Authorization header (SSRF / credential exfiltration).
- Missing guard: MINIMAX_API_HOST (and the generic _API_HOST suffix) was not in the workspace dotenv blocklist, so the untrusted host override reached the credentialed outbound request.

## Fix
The fix adds MINIMAX_API_HOST to BLOCKED_WORKSPACE_DOTENV_KEYS and generalizes the suffix blocklist to BLOCKED_WORKSPACE_DOTENV_SUFFIXES = ["_API_HOST", "_BASE_URL"], so workspace dotenv can no longer inject MINIMAX_API_HOST, and env-driven URL routing is removed from the affected MiniMax request path.

## Scanner Expectation
Flag the workspace dotenv host-override blocklist at lines 71-72 (suffix list only _BASE_URL, MINIMAX_API_HOST absent from the key set) as an incomplete denylist allowing untrusted env-driven endpoint redirection of a credentialed outbound request (SSRF).
