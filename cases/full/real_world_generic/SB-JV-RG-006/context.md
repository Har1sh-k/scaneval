# SB-JV-RG-006: OpenAM Session Service RPC GetSessionCount exposes arbitrary users' sessions (Improper Authorization)

## Advisory
- Repo: `OpenIdentityPlatform/OpenAM`
- GHSA: `GHSA-vvhj-w2jq-263q`
- CVE: `CVE-2026-45048`
- Vulnerable commit: `4529f108e9f5d3b8f98b4afb3dd035a3c4d73a1b` (release 16.0.6)
- Fix commit: `f775b42236b3cb94e3a02a19f4a4f4f5cc0b91c4` (release 16.1.1)

## Vulnerability
The target UUID is taken directly from the incoming SessionRequest (req.getUUID()) and passed unvalidated to sessionQueryManager.getAllSessionsByUUID(uuid), which returns session data for that arbitrary user. No ownership or privilege check ties the requester's session to the queried UUID, so the GetSessionCount path leaks other users' sessions to any authenticated caller.

## Source / Carrier / Sink
- Source: Attacker-controlled UUID field of the SessionRequest sent to the stateful session service endpoint (read via req.getUUID()).
- Carrier: The String uuid value flows from req.getUUID() directly into the sessionQueryManager.getAllSessionsByUUID(uuid) lookup within the GetSessionCount case of processMethod.
- Sink: sessionQueryManager.getAllSessionsByUUID(uuid) followed by res.setSessionsForGivenUUID(sessions), which returns the queried user's active session map to the caller.
- Missing guard: No ownership or administrative-privilege authorization check linking the requesting session to the queried UUID; verifyValidRequest only rejects restricted tokens, not cross-user access.

## Fix
The fix (commit f775b42236b3, released in 16.1.1) removes the GetSessionCount capability entirely: verifyValidRequest now throws an unknownRequestMethod SessionRequestException for GetSessionCount/GetValidSessions instead of allowing it, and the GetSessionCount case in processMethod (which called getAllSessionsByUUID) is commented out. The session-quota query is treated as internal-only and is no longer reachable over the RPC.

## Scanner Expectation
Flag the data flow from the request-controlled req.getUUID() into sessionQueryManager.getAllSessionsByUUID and the returned session data as an improper-authorization / sensitive-information-exposure issue (CWE-285/CWE-200): a user-supplied principal identifier reaching a privileged session lookup with no ownership/role check.
