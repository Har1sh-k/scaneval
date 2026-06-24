# SB-TS-RW-113: Missing credential authorization check in dynamic-node-parameters allows foreign credential replay

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-r4v6-9fqc-w5jr`
- CVE: `CVE-2026-42226`
- Vulnerable commit: `bc9cbea6c94dda489a0daf872373b100d019cab0` (release n8n@2.17.4)
- Fix commit: `ac411127314921aaf82b7b97d76eeaa2703b708c` (release n8n@2.17.5)

## Vulnerability
refineResourceIds verifies workflow and project access but never checks that the caller is permitted to use the credential id passed in the request body, so a foreign credential id is accepted and later decrypted and used. Because the caller also controls the destination URL in the helper path, the leaked credential is replayed against attacker infrastructure.

## Source / Carrier / Sink
- Source: Attacker-controlled credentials (INodeCredentials with a credential id) and destination URL in the authenticated dynamic-node-parameters request body.
- Carrier: The credentials object is carried through the dynamic-node-parameters service into getWorkflow() and attached to node.credentials for the helper execution.
- Sink: Backend decryption and use of the referenced credential within the dynamic-node-parameters helper execution path that contacts the caller-controlled URL.
- Missing guard: No authorization check that the authenticated caller owns or has credential:read access to the supplied credential id before it is resolved and used.

## Fix
The fix extends refineResourceIds to accept payload.credentials, extracts the credential ids, and calls credentialsFinderService.findCredentialIdsWithScopeForUser with the credential:read scope; if any supplied id is not accessible to the user it throws ForbiddenError, rejecting the request.

## Scanner Expectation
Flag that a credential id taken from the request body reaches a credential-resolution/use sink without any per-user authorization (ownership/scope) check in the request-sanitizing path.
