# SB-TS-RW-110: SQL injection in Data Table Get node via unescaped orderByColumn identifier

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-98c2-4cr3-4jc3`
- CVE: `CVE-2026-33713`
- Vulnerable commit: `2374f40ec36795904b4011fb81018da818a76ee8` (release n8n@2.14.0)
- Fix commit: `2d9a2ec76e180b54e8091e31b1e0638c909abd99` (release n8n@2.14.1)

## Vulnerability
The orderByColumn value is attacker-controllable (a node parameter that can be an expression) and reached quoteIdentifier without any escaping of the double-quote terminator; the function returned `"${name}"`, so a payload like col"; DROP ... closes the identifier and appends attacker SQL into the generated ORDER BY query.

## Source / Carrier / Sink
- Source: Data Table Get node 'orderByColumn' parameter (workflow author input, can incorporate expressions / external data).
- Carrier: orderByColumn -> sortBy -> DataTableRowsRepository.applySortingByField(query, field, direction) -> quoteIdentifier(field, dbType).
- Sink: quoteIdentifier interpolates the column name into the ORDER BY SQL string used by query.orderBy().
- Missing guard: No escaping of double quotes within the quoted identifier (and no column-name allowlist/validation) before building the SQL.

## Fix
quoteIdentifier now escapes embedded double quotes by doubling them (name.replace(/"/g, '""')) before wrapping, and the surrounding fix adds isValidColumnName validation in applySortingByField and column-existence checks in the Get operation, so an invalid/injecting column name is rejected.

## Scanner Expectation
Flag quoteIdentifier returning `"${name}"` with an unescaped, untrusted identifier interpolated into a SQL string as SQL injection via identifier.
