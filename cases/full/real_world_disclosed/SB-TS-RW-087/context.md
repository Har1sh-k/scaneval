# SB-TS-RW-087: Flowise chatflow update endpoint mass-assigns request body, allowing cross-workspace reassignment and deploy/visibility tampering

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-5wxp-qjgq-fx6m`
- CVE: `CVE-2026-42863`
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `0d29e4d0dfa3119c4ace89f615340d40b0615c9e` (release flowise@3.1.2)

## Vulnerability
The handler trusts the full client body and Object.assigns it onto a database entity with no DTO allowlist, so the user controls the workspaceId ownership key that determines authorization scope as well as security-relevant flags like isPublic and deployed. Because no check confirms the supplied workspaceId belongs to the caller, the chatflow can be reassigned to any workspace, bypassing the tenant-isolation authorization boundary.

## Source / Carrier / Sink
- Source: Authenticated user's HTTP JSON request body (req.body) sent to PUT /api/v1/chatflows/{id}.
- Carrier: req.body assigned to local `body` and passed to Object.assign into a new ChatFlow entity, including server-controlled keys like workspaceId, deployed and isPublic.
- Sink: Object.assign(updateChatFlow, body) followed by chatflowsService.updateChatflow, which merges and saves the entity to the database.
- Missing guard: No field allowlist / stripping of protected fields and no check that body.workspaceId matches the caller's authorized workspace; the user-controlled ownership key is accepted as-is.

## Fix
Commit 0d29e4d (flowise@3.1.2) wraps the assignment with a new stripProtectedFields() helper (Object.assign(updateChatFlow, stripProtectedFields(body))) so protected fields including workspaceId and timestamps are removed from client input, and the service reassigns the trusted workspaceId param onto the merged entity before saving.

## Scanner Expectation
A scanner should flag the flow from req.body to Object.assign onto a persisted ORM entity (CWE-915 mass assignment) where a user-controlled ownership key (workspaceId, CWE-639) crosses the authorization boundary with no allowlist or ownership re-validation.
