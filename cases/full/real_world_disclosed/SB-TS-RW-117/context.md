# SB-TS-RW-117: SQL injection in Oracle Database node select operation via unsanitized Limit field

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-r6jc-mpqw-m755`
- CVE: `CVE-2026-42233`
- Vulnerable commit: `6336f0a447eab3600b1fe13216f1abd5b6e25dff` (release n8n@2.18.0)
- Fix commit: `1a27bb32564c5b300eff9af6dc22093f1451414b` (release n8n@2.18.1)

## Vulnerability
The limit parameter is taken verbatim from user/expression-controlled input and string-interpolated into the SQL statement without being cast to an integer or bound as a query parameter. Since the column lists, schema, and table are quoted via quoteSqlIdentifier and the WHERE values are parameterized, the Limit field is the one place where raw user input reaches the SQL text, making it a direct SQL injection sink.

## Source / Carrier / Sink
- Source: User/expression-controlled input supplied to the Oracle Database node's `Limit` field (e.g. an expression resolving from a webhook payload).
- Carrier: The `limit` local read via this.getNodeParameter('limit', i, 50) without numeric coercion.
- Sink: Template-literal SQL construction interpolating `${limit}` into `FETCH FIRST ${limit} ROWS ONLY` and `WHERE ROWNUM <= ${limit}`, later executed by runQueries against Oracle.
- Missing guard: No integer coercion/validation or parameter binding of the limit value before it is interpolated into the SQL string (the fix's Number.isFinite/Math.trunc cast).

## Fix
The fix coerces the limit to a safe integer before interpolation: `const limitParam = this.getNodeParameter('limit', i, 50); const limit = Number.isFinite(Number(limitParam)) ? Math.trunc(Number(limitParam)) : 0;`. Using Number()/Number.isFinite()/Math.trunc() guarantees a finite integer (or 0) is interpolated, so attacker-supplied non-numeric SQL fragments can no longer reach the query string.

## Scanner Expectation
Flag the data flow from the user-controlled `limit` node parameter into the interpolated SQL template literal (FETCH FIRST / ROWNUM clause) executed against the database as SQL injection (CWE-89/CWE-20) lacking sanitization or parameterization.
