# SB-TS-RW-097: Zendesk Trigger webhook accepts unsigned requests (missing HMAC-SHA256 signature verification)

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-38c7-23hj-2wgq`
- CVE: ``
- Vulnerable commit: `df8bafc24fa13dad25d498928533d64b2acf128d` (release n8n@2.6.1)
- Fix commit: `4622acaccc69afb9720390e8e0011f490208fd1a` (release n8n@2.6.2)

## Vulnerability
webhook() calls this.getRequestObject() and passes req.body straight into returnJsonArray with no authentication step, so there is no check that the request actually originated from Zendesk. Because the signing secret is never fetched or used to validate the request signature, a forged webhook delivery is indistinguishable from a genuine one.

## Source / Carrier / Sink
- Source: Attacker-controlled HTTP POST to the workflow's Zendesk Trigger webhook URL (the request body).
- Carrier: this.getRequestObject().body, passed via this.helpers.returnJsonArray into the workflow trigger output.
- Sink: Return of workflowData from webhook() (line 429), which starts the workflow with the unauthenticated request body.
- Missing guard: No HMAC-SHA256 signature verification of the request against Zendesk's signing secret before the body is accepted (the fix's verifySignature() 401 gate).

## Fix
The fix fetches Zendesk's webhook signing secret during webhook creation and adds a verifySignature() helper that recomputes the HMAC-SHA256 over the request body and compares it to the signature header; webhook() now calls verifySignature() first and responds 401 Unauthorized for unsigned/forged requests before any workflow data is produced.

## Scanner Expectation
Flag the webhook trigger handler that consumes the inbound request body as workflow input with no signature/authentication check as an authentication-bypass-by-spoofing (CWE-290) webhook-forgery sink.
