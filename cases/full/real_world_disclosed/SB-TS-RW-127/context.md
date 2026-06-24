# SB-TS-RW-127: NoSQL injection in MongoDB node Find And Replace via unvalidated updateKey filter value

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-jpq7-226w-6cxx`
- CVE: `CVE-2026-54313`
- Vulnerable commit: `ded6282794347306df6cba7f7c39876786b2d24d` (release n8n@2.23.4)
- Fix commit: `439d2601815a72bf93ca185af1e5b49c520fa9af` (release n8n@2.24.0)

## Vulnerability
The value used in the equality filter (`item[updateKey]`) was taken straight from user-supplied item JSON and passed to findOneAndReplace with no constraint on its type. MongoDB treats an object value as query operators rather than a literal, so a crafted object turns the intended single-document match into an operator-based query that can match and replace arbitrary documents.

## Source / Carrier / Sink
- Source: The updateKey field value within the user-supplied item JSON for the MongoDB Find And Replace operation (authenticated workflow editor).
- Carrier: item[updateKey] returned from prepareItems and used to construct the equality filter object.
- Sink: collection.findOneAndReplace(filter, item, ...) where filter = { [updateKey]: item[updateKey] } is sent to MongoDB as the match query.
- Missing guard: No type validation rejecting object/array values for the updateKey before building the MongoDB filter, allowing query operators to be injected.

## Fix
The fix adds an `isScalarUpdateKeyValue` guard in prepareItems (GenericFunctions.ts) that throws a NodeOperationError when the updateKey field value is not a string, number, boolean, bigint, Date or null, explicitly rejecting objects and arrays as the match value; prepareItems now receives the node and the operation handlers call it inside the try block so the validation runs before the filter is used.

## Scanner Expectation
Flag the findOneAndReplace filter construction that uses an unvalidated user-controlled item[updateKey] value as a MongoDB query filter (NoSQL injection sink).
