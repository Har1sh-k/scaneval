# SB-TS-RW-098: GitHub Webhook Trigger accepts unsigned requests (missing HMAC-SHA256 signature verification)

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-mqpr-49jj-32rc`
- CVE: ``
- Vulnerable commit: `e040ab67e5acf63df4438a7f9352ab91cd43ccc4` (release n8n@2.4.8)
- Fix commit: `64c9148e1d65ad9e666bf37cf71720b876b58926` (release n8n@2.5.0)

## Vulnerability
webhook() consumes this.getBodyData() and (aside from a ping short-circuit) pushes the body/headers/query straight into the workflow output with no authentication, and the hook was created without a `secret`, so there is no HMAC for the handler to check. Any request reaching the webhook URL is therefore treated as a genuine GitHub delivery.

## Source / Carrier / Sink
- Source: Attacker-controlled HTTP POST to the workflow's GitHub Trigger webhook URL (the request body/headers).
- Carrier: this.getBodyData() (plus header/query data), accumulated into returnData and emitted via this.helpers.returnJsonArray.
- Sink: Return of workflowData from webhook() (line 636), which starts the workflow with the unauthenticated request body.
- Missing guard: No HMAC-SHA256 (X-Hub-Signature-256) signature verification against a shared webhook secret before the body is accepted (the fix's verifySignature() 401 gate plus secret registration).

## Fix
The fix generates a random 32-byte webhook secret, registers it in the GitHub hook config so GitHub signs deliveries, stores it in webhookData, and adds a verifySignature() helper; webhook() now calls verifySignature() first and returns 401 Unauthorized for requests whose HMAC-SHA256 signature does not match before producing any workflow data.

## Scanner Expectation
Flag the webhook trigger handler that consumes the inbound request body as workflow input without any signature/authentication check as an authentication-bypass-by-spoofing (CWE-290) webhook-forgery sink.
