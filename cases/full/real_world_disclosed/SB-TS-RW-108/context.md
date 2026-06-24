# SB-TS-RW-108: RCE via SQL mode of Merge node (AlaSQL file-access functions not disabled)

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-58qr-rcgv-642v`
- CVE: `CVE-2026-33660`
- Vulnerable commit: `ef9e32b27a784d88c034cfe6fb1f25cca2e9bbd3` (release ?)
- Fix commit: `79f1cca9af0ad92b08356cbd2f70d83f512edb6e` (release n8n@1.123.27)

## Vulnerability
The execute() handler takes the operator-controlled query parameter, resolves expressions into it, and runs it via AlaSQL's db.exec() with all of AlaSQL's built-in file and loader functions intact. Because nothing restricts the SQL surface, statements invoking FILE/LOAD/CSV/JSON-style handlers reach the file system and engine layer, enabling host file read and code execution.

## Source / Carrier / Sink
- Source: User-supplied SQL query parameter of the Merge node (this.getNodeParameter('query', 0)).
- Carrier: The resolved query string passed through getResolvables/evaluateExpression into a local variable.
- Sink: db.exec(query) on the AlaSQL Database, which interprets file-access/loader SQL functions.
- Missing guard: No disabling of AlaSQL file-access functions (FILE/LOAD/CSV/JSON/SAVE) before executing the query.

## Fix
The fix introduces disableAlasqlFileAccess() and calls it at the start of execute(), overriding alasql.fn / alasql.from / alasql.engines entries (FILE, JSON, TXT, CSV, XLSX, XLS, LOAD, SAVE) with a function that throws, so file-access SQL is rejected before db.exec() runs the query.

## Scanner Expectation
Flag the AlaSQL db.exec(query) execution of attacker-controlled SQL without a guard restricting file/loader functions as code/command injection.
