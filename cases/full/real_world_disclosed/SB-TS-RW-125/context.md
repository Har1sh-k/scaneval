# SB-TS-RW-125: n8n MCP Browser HTTP transport accepts unauthenticated session init and tool invocation

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-qrx8-25qr-5r7v`
- CVE: `CVE-2026-54309`
- Vulnerable commit: `a37ba249d46c98cd3369450c9624bf00497ef9db` (release n8n@2.25.6)
- Fix commit: `3f7246b41a768a331efd7681a103cf30a293f725` (release n8n@2.25.7)

## Vulnerability
The HTTP transport handler performs no bearer-token check and no Origin validation before creating sessions and connecting the browser-control MCP server; combined with the wildcard CORS headers, this leaves the privileged browser-control endpoint completely open to unauthenticated and cross-origin callers. Any reachable client can therefore initialize a session and invoke tools against the live browser.

## Source / Carrier / Sink
- Source: Unauthenticated HTTP request to the @n8n/mcp-browser HTTP transport endpoint from any network-reachable client or web page.
- Carrier: node:http createServer request handler that routes MCP session-init and tool-invocation requests.
- Sink: StreamableHTTPServerTransport session creation and browser-control MCP tool invocation (navigation, JS eval, cookie/storage access) against the user's browser.
- Missing guard: Authentication (bearer-token verification) and Origin/Host validation on the HTTP request before establishing a session or serving tools.

## Fix
The fix introduces a required auth token (provided via --auth-token / env var or auto-generated) and rejects requests lacking a valid 'Authorization: Bearer <token>' (constant-time compared) with 401, and rejects any request carrying an Origin header with 403, before any session is created. It also binds to a configurable host (default 127.0.0.1) and enables DNS-rebinding/Host-header protection on loopback, replacing the unauthenticated wildcard-CORS handler.

## Scanner Expectation
Flag the HTTP server request handler that establishes privileged MCP browser-control sessions without any authentication or origin check (missing authentication on a sensitive endpoint).
