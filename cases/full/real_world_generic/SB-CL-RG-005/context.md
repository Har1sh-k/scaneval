# SB-CL-RG-005: H2 JDBC INIT injection via unsanitized database details in EE serialization import

## Advisory
- Repo: `metabase/metabase`
- GHSA: `GHSA-fppj-vcm3-w229`
- CVE: `CVE-2026-33725`
- Vulnerable commit: `aafb2706d5fdef69b099119f7d05d22163a2b8d3` (release v0.59.3)
- Fix commit: `88a87db2b8d2ca246c25a036517b09a81b0810c8` (release v0.59.4)

## Vulnerability
connection-details->spec :h2 forwards the raw details map (controlled by the imported serialization archive) into the H2 JDBC connection spec without removing dangerous low-level keys. An attacker-supplied INIT key is therefore preserved and executed as SQL by H2 at connection time, giving RCE/arbitrary file read.

## Source / Carrier / Sink
- Source: Attacker-controlled database connection details (the :details map) deserialized from an uploaded serialization archive at POST /api/ee/serialization/import.
- Carrier: The details map flows unchanged through serdes load into connection-details->spec :h2 and into the H2 JDBC connection spec.
- Sink: driver-api/spec :h2 builds the JDBC URL/spec from details; H2 executes the INIT property's SQL when the connection is opened during sync.
- Missing guard: No removal/rejection of dangerous JDBC keys (init, connection-uri, subname, subprotocol, classname) from imported details before constructing the H2 spec.

## Fix
The fix introduces driver/sanitize-db-details (stripping init, classname, subprotocol, connection-uri, subname) and wraps the details with (driver/sanitize-db-details details) before building the H2 spec; the serialization Database loader also sanitizes :details/:write_data_details and rejects H2 databases entirely on import.

## Scanner Expectation
Flag connection-details->spec :h2 (lines 548-552) for passing externally-controlled connection details into the H2 JDBC spec without sanitizing the INIT/low-level JDBC keys, enabling SQL/code execution at connection time.
