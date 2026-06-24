# SB-TS-RW-115: Unauthenticated chat WebSocket attaches to any execution by ID without authorization

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-f77h-j2v7-g6mw`
- CVE: `CVE-2026-42228`
- Vulnerable commit: `6336f0a447eab3600b1fe13216f1abd5b6e25dff` (release n8n@2.18.0)
- Fix commit: `85b7796434df7e80c4023666e2c0ede6e526a6ba` (release n8n@2.18.1)

## Vulnerability
The attacker-controlled executionId from the WebSocket query is used to look up and bind to an execution with no ownership, token, or authentication check beyond mere existence. Any party that knows a waiting execution's ID can hijack that pending chat session.

## Source / Carrier / Sink
- Source: Untrusted executionId (and sessionId) from the inbound /chat WebSocket connection query string parsed into req.query.
- Carrier: ChatService.startSession() destructures executionId from req.query and passes it directly to executionManager.checkIfExecutionExists().
- Sink: Binding the WebSocket to the located execution (ws.isAlive = true; session key built from executionId) so the attacker receives prompts and can post messages to that execution.
- Missing guard: No verification that the connecting client is authorized for the execution: no per-execution resume token check and no authentication requirement before attaching to the execution.

## Fix
The fix switches to executionManager.findExecution(executionId) to load the execution data and, when a resumeToken is present, requires the connection's token query parameter to match it using a constant-time timingSafeEqual comparison; mismatches and missing executions return a generic 'Connection rejected' and close the socket.

## Scanner Expectation
Flag that an attacker-controlled executionId from the request query reaches an execution-attachment/session-binding sink with only an existence check and no authorization or token validation.
