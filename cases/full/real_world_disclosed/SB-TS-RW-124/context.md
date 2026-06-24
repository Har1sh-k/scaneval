# SB-TS-RW-124: Authentication bypass in Microsoft Agent 365 Trigger via forged identity instead of JWT validation

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-jvc7-762p-3743`
- CVE: `CVE-2026-54308`
- Vulnerable commit: `a37ba249d46c98cd3369450c9624bf00497ef9db` (release n8n@2.25.6)
- Fix commit: `3f7246b41a768a331efd7681a103cf30a293f725` (release n8n@2.25.7)

## Vulnerability
Inbound requests were treated as authenticated by synthesizing a fake `req.user` from the node's own client ID rather than verifying the request's bearer token, so no real authentication occurred. Any request reaching the webhook endpoint was accepted and processed under that spoofed identity, allowing request forgery by unauthenticated callers.

## Source / Carrier / Sink
- Source: Unauthenticated HTTP request to the Microsoft Agent 365 Trigger webhook URL with an attacker-controlled payload.
- Carrier: The webhook request object, onto which a fabricated `req.user` was attached from credentials.clientId.
- Sink: agent.adapter.process(req, res, callback), which processes the activity trusting the (forged) req.user identity and triggers workflow execution.
- Missing guard: No verification of the inbound Bot Framework JWT (authorizeJWT) before treating the request as authenticated and processing it.

## Fix
The fix imports `authorizeJWT` from @microsoft/agents-hosting and runs `authorizeJWT(authConfig)(req, res, ...)` to verify the Bot Framework token (setting req.user only on success); if authorization fails it returns 401 (with a backstop res.status(401) when the middleware did not respond) and aborts before calling agent.adapter.process. createMicrosoftAgentApplication now also returns authConfig for this check.

## Scanner Expectation
Flag the webhook handler that fabricates an authenticated req.user from the node's own client ID and processes the request without validating the inbound token (authentication bypass).
