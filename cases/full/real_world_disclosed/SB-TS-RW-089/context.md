# SB-TS-RW-089: Flowise assistant update endpoint mass-assigns request body, allowing cross-workspace reassignment of assistants

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-hp26-q66v-q2w7`
- CVE: `CVE-2026-46441`
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `faa571c961ee0ebe6fb9f4d060beb54e293ad39b` (release flowise@3.1.2)

## Vulnerability
The CUSTOM update path blindly Object.assigns the client body onto a database entity with no DTO allowlist, letting the user control the workspaceId ownership key that governs authorization scope. Since nothing validates that the supplied workspaceId belongs to the caller, the assistant can be moved to any workspace, bypassing the tenant-isolation authorization boundary.

## Source / Carrier / Sink
- Source: Authenticated user's HTTP JSON request body (requestBody / req.body) sent to PUT /api/v1/assistants/{id}.
- Carrier: requestBody aliased to `body` and passed to Object.assign into a new Assistant entity, including server-controlled keys like workspaceId.
- Sink: Object.assign(updateAssistant, body) then repository.merge(assistant, updateAssistant) and repository.save(assistant), persisting the entity.
- Missing guard: No field allowlist / stripping of protected fields and no check that body.workspaceId matches the caller's authorized workspace; the user-controlled ownership key is accepted as-is.

## Fix
Commit faa571c (flowise@3.1.2) adds a stripProtectedFields() utility and applies Object.assign(assistant, stripProtectedFields(requestBody)) so protected fields (id, workspaceId, timestamps) are removed from the client input; the create/update paths also pass and reassign the trusted workspaceId explicitly.

## Scanner Expectation
A scanner should flag the flow from the client request body to Object.assign onto a persisted ORM entity (CWE-915 mass assignment) where a user-controlled ownership key (workspaceId, CWE-639) crosses the authorization boundary with no allowlist or ownership re-validation.
