# SB-TS-RW-103: Merge node SQL mode allows arbitrary file write (incomplete alasql file-access hardening, INTO handlers not disabled)

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-hv53-3329-vmrm`
- CVE: `CVE-2026-25056`
- Vulnerable commit: `a8cdf0f01cac8ba1f4452d2ecd9fcb16e0990b32` (release n8n@2.3.6)
- Fix commit: `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9` (release n8n@2.4.0)

## Vulnerability
disableAlasqlFileAccess() is a protection-mechanism that enumerates only some of alasql's file primitives; it omits the entire alasql.into write path and the alasql.utils file helpers. Because execute() then runs the raw user query via db.exec(query), the INTO file-write handlers remain live and the query can write to any filesystem path the n8n process can reach (no path normalisation/allowlist), giving arbitrary file write to a controllable location.

## Source / Carrier / Sink
- Source: Authenticated workflow author-controlled SQL query for the Merge node's combineBySql mode (the `query` parameter).
- Carrier: The raw `query` string passed unmodified into the alasql engine after the incomplete disableAlasqlFileAccess() hardening runs.
- Sink: db.exec(query) in execute() (combineBySql) which, via alasql's still-enabled INTO file-write handlers, writes attacker-controlled content to an attacker-chosen filesystem path.
- Missing guard: disableAlasqlFileAccess() does not disable alasql.into.* write handlers or alasql.utils file helpers (nor restrict the write path), so the SQL `INTO <file>` write capability survives the guard.

## Fix
The fix expands disableAlasqlFileAccess() to disable the full set of alasql file primitives: it adds alasql.into.* (FILE/TXT/CSV/JSON/SQL/XLS/XLSX/HTML...) write handlers, alasql.utils.{loadFile,loadBinaryFile,saveFile,removeFile,deleteFile,fileExists}, all file-based engines (FILE/FILESTORAGE/LOCALSTORAGE/INDEXEDDB/SQLITE...), and a broader set of FROM/fn handlers, so user SQL can no longer reach any file read or write engine.

## Scanner Expectation
Flag disableAlasqlFileAccess() as an incomplete protection mechanism (CWE-693) / arbitrary file write: the deny-list omits alasql's INTO file-write handlers, so user-controlled SQL reaching db.exec() can write files to an arbitrary path (CWE-434/CWE-22).
