# SB-TS-RW-126: SQL injection via unvalidated column cast type in Postgres v1/TimescaleDB node

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-c37g-w77q-m4vp`
- CVE: `CVE-2026-54310`
- Vulnerable commit: `a37ba249d46c98cd3369450c9624bf00497ef9db` (release n8n@2.25.6)
- Fix commit: `3f7246b41a768a331efd7681a103cf30a293f725` (release n8n@2.25.7)

## Vulnerability
The `cast` portion of each `name:cast` column definition comes straight from the user-supplied `columns` parameter and is passed unmodified into pgp.helpers.ColumnSet, which renders the cast as raw SQL rather than a bound parameter. Because nothing constrains the cast to a valid type name, an attacker can break out of the cast position and inject arbitrary SQL into the generated INSERT/UPDATE statement.

## Source / Carrier / Sink
- Source: The `columns` (and `updateKey`) node parameter supplied by an authenticated user with workflow create/edit permission.
- Carrier: The `cast` token parsed from each `name:cast` column definition and stored in the column descriptor objects.
- Sink: pgp.helpers.ColumnSet(columns, ...) which renders each column's cast as raw, non-parameterized SQL in the generated INSERT/UPDATE query.
- Missing guard: No validation of the cast string against an allowlist/regex of valid PostgreSQL type names before it is embedded into the SQL.

## Fix
The fix adds an `assertValidCast` helper that validates each parsed cast against a strict POSTGRES_TYPE_PATTERN regex (allowing only well-formed type names, optional schema/precision and array suffixes) and throws an ApplicationError on any other value. assertValidCast is invoked for every column cast and updateKey cast in pgInsert, pgInsertV2, pgUpdate and pgUpdateV2 before the ColumnSet is built.

## Scanner Expectation
Flag the column/cast parsing that feeds the user-controlled `cast` into pgp.helpers.ColumnSet (raw SQL type) without validating it, in the Postgres v1 pgInsert/pgUpdate code paths.
