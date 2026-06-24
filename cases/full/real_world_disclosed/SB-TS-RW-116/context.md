# SB-TS-RW-116: SQL injection in n8n SeaTable node row:search via unescaped query interpolation

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-mp4j-h6gh-f6mp`
- CVE: `CVE-2026-42229`
- Vulnerable commit: `e7d95055d1ab260ae91f8ba358310211476bd677` (release n8n@1.123.31)
- Fix commit: `0e626768ed19d97f3f2aa98c9f1d4021c73ee7e6` (release n8n@1.123.32)

## Vulnerability
tableName, searchColumn and searchTerm are taken straight from getNodeParameter and concatenated into the SeaTable SQL string with no escaping or parameterization, so any of them can carry SQL metacharacters (backticks, quotes) that alter the query structure. Because expression-mapped values can come from untrusted external sources, this turns the search into a classic string-concatenation SQL injection sink.

## Source / Carrier / Sink
- Source: User-controlled SeaTable node parameters tableName/searchColumn/searchTerm (often expression-mapped from a form/webhook) read via getNodeParameter.
- Carrier: The searchTermString/tableName/searchColumn values concatenated into the sqlQuery template string.
- Sink: The sqlQuery string sent to the SeaTable /api-gateway .../sql/ endpoint via seaTableApiRequest.
- Missing guard: No SQL identifier/string escaping or parameterization of tableName, searchColumn or searchTerm before interpolation.

## Fix
The fix adds escapeSqlIdentifier (escapes backticks) and escapeSqlString (escapes backslash and quotes) helpers in the SeaTable GenericFunctions and wraps every interpolated value: identifiers via escapeSqlIdentifier(tableName)/escapeSqlIdentifier(searchColumn) and the search term via escapeSqlString(searchTermString) (and escapeSqlString(rowId) in row:get), so user input can no longer break out of the query.

## Scanner Expectation
Flag the SELECT query built by string-concatenating untrusted searchTerm/tableName/searchColumn into sqlQuery without escaping, executed against the SeaTable SQL gateway.
