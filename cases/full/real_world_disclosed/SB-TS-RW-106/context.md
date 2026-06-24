# SB-TS-RW-106: RCE via Merge node SQL query mode (unrestricted alasql execution)

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-wxx7-mcgf-j869`
- CVE: `CVE-2026-27497`
- Vulnerable commit: `8e81f3e31398b04fd6f8cc27cf844980cd382117` (release n8n@2.10.0)
- Fix commit: `562d867483e871b0f1e31776252e23bd721df75b` (release n8n@2.10.1)

## Vulnerability
The query parameter is attacker-controlled (set in the workflow) and is passed verbatim to db.exec(query) on a full alasql Database, which supports far more than read-only SELECT (file I/O via FILE/SAVE/LOAD and code loading via REQUIRE / inline JavaScript). The pre-patch disableAlasqlFileAccess() guard was incomplete and left the REQUIRE/JavaScript code-execution surface open, enabling RCE.

## Source / Carrier / Sink
- Source: Merge node 'query' parameter (combineBySql operation), set by an authenticated workflow author and resolved from expressions.
- Carrier: The query string passed to executeSelectWithMappedPairedItems / execute and on to db.exec().
- Sink: db.exec(query) on the alasql Database instance, which interprets alasql SQL including file I/O and code-loading statements.
- Missing guard: No restriction of the alasql command surface to safe read-only SQL: the REQUIRE statement and inline JavaScript execution paths were not disabled before exec.

## Fix
The fix replaces the static alasql import with a cached, hardened instance and a disableUnsafeAccess() routine that additionally blocks the REQUIRE statement (alasql.fn.REQUIRE, alasql.utils.require, the Require statement prototype), the inline JavaScript engine (alasql.yy.JavaScript), and freezes alasql.fn, before any user query is executed.

## Scanner Expectation
Flag the alasql db.exec(query) call where query originates from a node parameter as code/command injection (untrusted input reaching a code-interpreting sink).
