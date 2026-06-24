# SB-CL-RG-006: Data access control bypass via client-supplied query permission context on card creation

## Advisory
- Repo: `metabase/metabase`
- GHSA: `GHSA-433r-hw2v-rv9g`
- CVE: ``
- Vulnerable commit: `dcef702a8ca6c1cc079ae6004af6c6d7aee1790f` (release v0.54.22)
- Fix commit: `17c12b5707085207703f63329ed2898e09e9cdf8` (release v0.54.23)

## Vulnerability
The permission check ran against the query object exactly as received from the client, including the :query-permissions/perms key that encodes the effective permission context. Because that key was attacker-controllable and trusted rather than recomputed on the server, a user could attach a permissive context to bypass data-access checks and run native SQL against unauthorized tables/databases.

## Source / Carrier / Sink
- Source: Client-supplied dataset_query in POST/PUT /api/card, including the attacker-controlled :query-permissions/perms permission context.
- Carrier: The query map passed unchanged into card/check-run-permissions-for-query for the permission check.
- Sink: Permission check / query execution that honors the embedded :query-permissions/perms context.
- Missing guard: Failure to strip and re-derive the permission context server-side before checking run permissions.

## Fix
The fix strips the client-supplied permission context before the check by calling (dissoc query :query-permissions/perms) (and (dissoc (:dataset_query card-updates) :query-permissions/perms) on update) so check-run-permissions-for-query re-derives authorization server-side; companion changes also strip injected :persisted-info/native and re-validate query parameters at the API boundary.

## Scanner Expectation
Flag passing the raw client query into check-run-permissions-for-query without dissoc'ing :query-permissions/perms, allowing a client-supplied permission context to drive the authorization decision.
