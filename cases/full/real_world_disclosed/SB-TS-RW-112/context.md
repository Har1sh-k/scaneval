# SB-TS-RW-112: External secrets authorization bypass: credential save resolves $secrets without externalSecret:list check

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-fxcw-h3qj-8m8p`
- CVE: `CVE-2026-33722`
- Vulnerable commit: `c49c9c772096d4d10845693f54faaf50a7143cf4` (release n8n@2.6.3)
- Fix commit: `2b73ce4288d4bbb57ee20ddffcf3a5015895890b` (release n8n@2.6.4)

## Vulnerability
The credential-save validation path (checkCredentialData) checked only mandatory fields and OAuth URLs and never verified that the calling user held the externalSecret:list permission before resolving and persisting $secrets expressions. Any authenticated user could therefore reference a vault secret by name and retrieve its plaintext value despite lacking the listing permission.

## Source / Carrier / Sink
- Source: An external-secret expression ($secrets.<vault>.<key>) supplied in credential data by an authenticated user without externalSecret:list permission.
- Carrier: CredentialRequest credential data flowing into CredentialsService.checkCredentialData / prepareUpdateData on credential create/update.
- Sink: Resolution and persistence of the referenced vault secret value, exposing its plaintext to the requesting user.
- Missing guard: No externalSecret:list permission check before accepting and resolving $secrets references in credential data.

## Fix
Commit 2b73ce42 added a new validation.ts with validateExternalSecretsPermissions(), which detects $secrets expressions in the (changed) credential data and throws BadRequestError unless the user has the externalSecret:list global scope; it is invoked from checkCredentialData and prepareUpdateData (which now receive the User).

## Scanner Expectation
Flag the credential-save validation routine that resolves/persists $secrets references without enforcing the externalSecret:list authorization scope as a broken-access-control (authz bypass) sink.
