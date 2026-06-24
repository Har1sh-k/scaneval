# SB-TS-RW-118: SQL injection in n8n Snowflake (and legacy MySQL v1) nodes via unescaped identifiers

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-hp3c-vfpm-q4f7`
- CVE: `CVE-2026-42237`
- Vulnerable commit: `e7d95055d1ab260ae91f8ba358310211476bd677` (release n8n@1.123.31)
- Fix commit: `0e626768ed19d97f3f2aa98c9f1d4021c73ee7e6` (release n8n@1.123.32)

## Vulnerability
table, columns and updateKey come straight from getNodeParameter and are concatenated into INSERT/UPDATE templates without escaping, so identifier values containing SQL metacharacters change the query structure. Only the row data is parameterized (?), leaving the identifier positions as a string-concatenation SQL injection sink.

## Source / Carrier / Sink
- Source: User-controlled Snowflake/MySQL v1 node parameters table, columns and updateKey (expression-mappable from external input) read via getNodeParameter.
- Carrier: The table/columns/updateKey strings concatenated into the INSERT/UPDATE query template.
- Sink: The constructed query passed to execute()/connection.query() against the Snowflake/MySQL database.
- Missing guard: No identifier escaping or binding for table/column/updateKey before interpolation into the SQL string.

## Fix
The Snowflake node fix switches identifiers to bound IDENTIFIER(?) placeholders (e.g. INSERT INTO IDENTIFIER(?)(IDENTIFIER(?),...) and UPDATE IDENTIFIER(?) SET IDENTIFIER(?) = ?...) with table/columns/updateKey passed via binds. The MySQL v1 node fix wraps identifiers with escapeSqlIdentifier (imported from the MySQL v2 helpers) in both the INSERT and UPDATE builders.

## Scanner Expectation
Flag the INSERT/UPDATE queries built by concatenating untrusted table/columns/updateKey identifiers into the SQL string without escaping (parameter binding only protects the row values, not the identifiers).
