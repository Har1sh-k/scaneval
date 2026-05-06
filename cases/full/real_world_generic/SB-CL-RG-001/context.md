# SB-CL-RG-001 — Metabase H2 connection string RCE (follow-up advisory)

## Summary

Metabase lets administrators add data sources by supplying a JDBC-style connection string. For H2 this is a string like `file:my-db;OPTION=foo`. H2's `INIT` connection option runs arbitrary SQL when a connection is opened, and once SQL is running on H2 it can install user-defined Java code via `CREATE ALIAS` — i.e., remote code execution on the Metabase server.

A previous Metabase fix tried to scrub `INIT` from H2 connection strings before passing them to JDBC. CVE-2023-37470 follows up with bypass vectors that the previous fix did not handle, leading to the new fix that delegates parsing to H2's own `ConnectionInfo` and rejects malicious property values.

## Why it is a real bug

In `src/metabase/driver/h2.clj`, the vulnerable flow is:

1. `connection-details->spec :h2` accepts `details` with a `:db` string and calls `connection-string-set-safe-options`.
2. `connection-string-set-safe-options` splits the string on `;` (`connection-string->file+options`) and removes only options whose key equals `"init"` (case-insensitive on the *naive* split).
3. The resulting string is then handed to JDBC as the H2 connection URL.

H2 itself parses the connection string with different rules. Connection strings that pass through Metabase's filter — for example by hiding the `INIT` payload behind syntactic forms not normalised by the naive `;`-split — still reach H2 with an active `INIT` clause, executing the embedded SQL on connection.

The fixed code rejects entire connection strings whose H2-parsed properties contain `;`, `INIT`, or scripting-language markers (`//javascript`, `#ruby`, `//groovy`, `@groovy`).

## What a SAST tool should flag

A scanner that follows admin-supplied JDBC connection strings into `getConnection`-style calls without canonical parsing/validation should flag this region. The annotated lines cover the unsafe `connection-string-set-safe-options` routine and its caller `connection-details->spec`, where the unsanitised string is committed to the JDBC spec.

## References

- Advisory: <https://github.com/metabase/metabase/security/advisories/GHSA-p7w3-9m58-rq83>
- CVE: CVE-2023-37470
- Fix: metabase/metabase commit `11c35678659c` (PR #32733)
- Vulnerable snapshot: metabase/metabase at `398972be3a05`
