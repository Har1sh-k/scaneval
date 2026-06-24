# SB-TS-RW-120: Source Control Pull imports Data Table column name and table ID into raw DDL SQL without validation

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-mhrx-qhrj-673w`
- CVE: `CVE-2026-44792`
- Vulnerable commit: `29d42560ad14983ceb3dcda8cab0a1988d932a5d` (release n8n@2.20.6)
- Fix commit: `545da1aa8f9389532ee71a33a0e1beb93ad86591` (release n8n@2.20.7)

## Vulnerability
The import loop trusts the parsed JSON: it never validates dataTable.id or column.name against the safe data-table identifier/column-name schemas before they reach the DDL service. toTableName() concatenates the unvalidated id into the table name with no quoting, and that string is interpolated into raw CREATE/ALTER TABLE SQL run via em.query(), so a crafted id (or column name on the new-table path through toDslColumns, which also lacks the name check) breaks out of the intended identifier and injects SQL.

## Source / Carrier / Sink
- Source: Attacker-controlled Data Table JSON file (crafted dataTable.id / column name) committed to the git repository connected to Source Control.
- Carrier: Parsed ExportableDataTable object whose id and column names are passed unvalidated into the column upsert loop on Source Control Pull.
- Sink: DataTableDDLService renameColumn/addColumn/createTableWithColumns building raw ALTER/CREATE TABLE SQL (table name via toTableName(dataTable.id)) executed with em.query() on PostgreSQL.
- Missing guard: Validation of dataTable.id (isValidDataTableId) and column.name (isValidColumnName) against the safe identifier schemas before use in DDL SQL.

## Fix
The fix adds isValidColumnName and isValidDataTableId helpers (sql-utils.ts, backed by the api-types schemas) and calls them in the import loop: data tables whose id fails isValidDataTableId are skipped before import, and columns whose name fails isValidColumnName are skipped before any DDL operation, preventing untrusted identifiers from reaching the raw SQL.

## Scanner Expectation
Flag untrusted Data Table id/column-name values flowing from imported JSON into DDL service calls that build raw SQL identifiers (SQL injection via unsanitized identifier).
