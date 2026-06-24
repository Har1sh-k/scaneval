# SB-JV-RG-005: OpenAM authenticated SSRF via /sessionservice addSessionListener notification URL

## Advisory
- Repo: `OpenIdentityPlatform/OpenAM`
- GHSA: `GHSA-c556-q2mh-477v`
- CVE: `CVE-2026-44202`
- Vulnerable commit: `4529f108e9f5d3b8f98b4afb3dd035a3c4d73a1b` (release 16.0.6)
- Fix commit: `a13a4b63ae0e0670c63cbcfa79586407408b3920` (release 16.1.1)

## Vulnerability
The notification URL originates from the attacker-controlled session request (req.getNotificationURL()) and is stored and later fetched server-side via internalSession.addSessionEventURL(url, sessionId) without any host allow-listing or privilege/authorization check on the caller. Any authenticated user could thus register an arbitrary destination that OpenAM will later call out to.

## Source / Carrier / Sink
- Source: Attacker-controlled notification URL in the AddSessionListener SessionRequest sent to the /sessionservice endpoint (read via req.getNotificationURL()).
- Carrier: The url string flows from req.getNotificationURL() in SessionRequestHandler.processMethod through SessionService.addSessionListener into LocalOperations.addSessionListener as the url parameter.
- Sink: internalSession.addSessionEventURL(url, sessionId) registers the URL; OpenAM later performs outbound server-side HTTP notification requests to it (SSRF sink).
- Missing guard: No authorization check restricting addSessionListener to admin/server/agent callers and no validation/allow-listing of the notification URL host before registration.

## Fix
The fix (commit a13a4b63ae0e, released in 16.1.1) threads the caller's SSOToken (clientToken) through the addSessionListener call chain and adds checkAddSessionListenerPermission in LocalOperations, which rejects the request (throws IllegalArgumentException 'Request should be authenticated') unless the client token is an admin or an APPLICATION-type (server/agent) session, gated by the org.openidentityplatform.session.listener.skip-auth-check system property.

## Scanner Expectation
Flag the data flow from the request-controlled notification URL (req.getNotificationURL()) into LocalOperations.addSessionListener / internalSession.addSessionEventURL(url, ...) as an SSRF (CWE-918): a user-supplied URL reaching a server-side request registration with no host allow-listing or caller-privilege check.
