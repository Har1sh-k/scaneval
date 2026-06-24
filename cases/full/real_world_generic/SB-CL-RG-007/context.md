# SB-CL-RG-007: Entity-ID translation API routes mounted without authentication

## Advisory
- Repo: `metabase/metabase`
- GHSA: `GHSA-rxq7-9vqf-q9g8`
- CVE: ``
- Vulnerable commit: `227d50f7080c382541adc8e73949cef9f89a1948` (release v0.58.12)
- Fix commit: `73bd2a75a0687397dbb5af2b7f57627b9dc7a1e8` (release v0.58.13)

## Vulnerability
Every other authenticated API prefix in the route table is wrapped with the +auth middleware that enforces a valid session, but the /eid-translation entry was registered as a plain namespace symbol with no +auth wrapper (a source comment even noted the endpoints were public-facing). With no authentication gate, the translation endpoints accepted requests from anonymous users.

## Source / Carrier / Sink
- Source: Unauthenticated HTTP requests to /api/eid-translation/* with an attacker-supplied opaque entity identifier.
- Carrier: The Ring route table entry mounting the eid-translation namespace without an auth wrapper.
- Sink: The eid-translation API handlers performing entity-id lookups, reachable without a session.
- Missing guard: Missing +auth (authentication) middleware on the /eid-translation route prefix.

## Fix
The fix wraps the route in the authentication middleware, changing "/eid-translation" 'metabase.eid-translation.api to "/eid-translation" (+auth 'metabase.eid-translation.api) in routes.clj (and removes the stale 'these are public facing' comment in the eid_translation/api.clj namespace), so requests now require an authenticated session.

## Scanner Expectation
Flag the /eid-translation route mounted as a bare namespace without the +auth wrapper that gates every other authenticated API prefix in the route table.
