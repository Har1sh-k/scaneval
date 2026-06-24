# SB-CL-RG-008: Arbitrary file read via unvalidated MySQL/MariaDB JDBC connection options

## Advisory
- Repo: `metabase/metabase`
- GHSA: `GHSA-mfpj-crjq-xrcp`
- CVE: `CVE-2026-50147`
- Vulnerable commit: `eb9b113add06427cfe02744a0c8a32c5026227fa` (release v0.59.9)
- Fix commit: `57abd670097e33bab8cb8c597c31c9eb3917687d` (release v0.59.10)

## Vulnerability
The :additional-options string from the database connection form was appended to the JDBC URL and used to open a connection without any allow/deny validation of the option keys. Options like allowLoadLocalInfile/allowUrlInLocalInfile instruct the MySQL JDBC driver to read local files on behalf of the connecting server, turning an admin-controlled connection string into an arbitrary local file read.

## Source / Carrier / Sink
- Source: Admin-supplied MySQL/MariaDB connection :additional-options field in the database connection form.
- Carrier: JDBC additional-options string appended to the connection URL and passed to the MySQL JDBC driver.
- Sink: JDBC connection open in driver/can-connect? :mysql, where unsafe options trigger local file reads by the driver.
- Missing guard: No allow/deny-list validation of additional JDBC option keys before opening the connection.

## Fix
The fix adds a disallowed-additional-opts regex matching the dangerous option names and checks the :additional-options string in driver/can-connect? :mysql, throwing an ex-info ('Potentially dangerous keys in additional options') before any connection is opened when a match is found.

## Scanner Expectation
Flag the :mysql can-connect? method that forwards untrusted :additional-options into the JDBC connection without filtering dangerous file-reading option keys (allowLoadLocalInfile/allowUrlInLocalInfile/etc.).
