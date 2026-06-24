# SB-TS-RW-077: Flowise account registration mass-assigns req.body, letting unauthenticated users join arbitrary organizations and set roles

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-48m6-ch88-55mj`
- CVE: `CVE-2026-41267`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `1e4b0d87883e7f4086da985ca7d83c6e6088f027` (release flowise@3.1.0)

## Vulnerability
The handler trusts the entire request body as the registration DTO and forwards it unfiltered to the persistence layer, so authorization-relevant keys (organizationId, roleId, ownership/audit metadata) are controlled by the client rather than the server. There is no allowlist restricting which fields a registrant may set, so an attacker injects an existing organization's id and an owner role id and is persisted as a member of that tenant. The decision of which organization/role a new user belongs to, which must be server-enforced, is effectively delegated to untrusted input.

## Source / Carrier / Sink
- Source: Unauthenticated client JSON body of POST /api/v1/account/register (req.body), including attacker-chosen nested organization.id, organizationUser.organizationId, organizationUser.roleId and audit metadata.
- Carrier: AccountController.register() forwards req.body verbatim to AccountService.register(), which mass-assigns the nested objects onto User/Organization/OrganizationUser/Workspace entities.
- Sink: AppDataSource repository save of the merged entities persists the attacker-controlled organization association and role mapping for the new account.
- Missing guard: No allowlist/DTO validation of the registration body; server-managed and authorization-relevant fields (organization id, role id, createdBy/updatedBy) are accepted from the client instead of being set server-side.

## Fix
Fix commit 1e4b0d8 (Fix improper mass assignment in account registration #5689, shipped in flowise@3.1.0) adds a sanitizeRegistrationDTO() function in account.controller.ts that builds a fresh DTO containing only an explicit allowlist of user fields (name, email, credential, tempToken, referral) and organization.name, and register() now calls accountService.register(sanitizeRegistrationDTO(req.body)). All other client-supplied fields and nested objects (organization.id, organizationUser, roles, audit metadata) are dropped before persistence.

## Scanner Expectation
A scanner should flag that an unauthenticated request body flows unfiltered into entity creation/persistence (mass assignment), allowing user-controlled keys (organizationId/roleId) to drive authorization — CWE-639/CWE-915 authorization bypass through user-controlled key with no allowlist guard between source and sink.
