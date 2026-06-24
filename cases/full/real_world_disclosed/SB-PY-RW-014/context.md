# SB-PY-RW-014: Chat session hijack via IDOR in assign_user_to_session (missing ownership check)

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-q58p-v9r9-7gqj`
- CVE: `CVE-2026-30950`
- Vulnerable commit: `b342bfa3baaaa48b88fecef9edf8f8592059b0e7` (release autogpt-platform-beta-v0.6.50)
- Fix commit: `19d775c43578696baa1db1e0eaf93e701752fa2a` (release autogpt-platform-beta-v0.6.51)

## Vulnerability
The function deliberately passes None as the user_id to get_chat_session, which disables the per-user ownership check in copilot/model.py (the guard 'if user_id is not None and session.user_id != user_id' short-circuits to false). It then assigns the caller's user_id to the session without checking whether the session already belongs to someone else, so a session owned by another principal can be claimed by any authenticated caller.

## Source / Carrier / Sink
- Source: Authenticated user calling PATCH /api/chat/sessions/{session_id}/assign-user with an arbitrary (victim) session_id.
- Carrier: session_id flows into assign_user_to_session and then into get_chat_session(session_id, None), whose None user_id bypasses the ownership filter in the data-access layer.
- Sink: session.user_id = user_id followed by upsert_chat_session(session) reassigns ownership of the targeted session to the caller.
- Missing guard: An ownership/authorization check confirming the existing session.user_id is None or already equals the caller before reassigning (CWE-862 Missing Authorization).

## Fix
The fix commit (19d775c4) adds an authorization guard after loading the session: if session.user_id is not None and session.user_id != user_id it logs a [SECURITY] warning and raises NotAuthorizedError, preventing a caller from claiming a session that already belongs to a different user.

## Scanner Expectation
Detect a missing-authorization / IDOR access-control bypass: a per-object ownership check is intentionally skipped (user_id=None) and the object is mutated on behalf of an unauthorized principal.
