# SB-TS-RW-085: Flowise variable update endpoint mass-assigns request body, allowing cross-workspace reassignment of variables

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-6fw7-3q8r-m5vj`
- CVE: `CVE-2026-42861`
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `7dc48adbf02072d9b8ba406426cd8330a854943a` (release flowise@3.1.2)

## Vulnerability
The handler trusts the full client request body and uses Object.assign to map it onto a database entity with no DTO allowlist, so the user controls the workspaceId ownership key that determines authorization scope. Because no check confirms the supplied workspaceId belongs to (or equals) the caller's workspace, the user can reassign the resource to any workspace, bypassing the tenant-isolation authorization boundary.

## Source / Carrier / Sink
- Source: Authenticated user's HTTP JSON request body (req.body) sent to PUT /api/v1/variables/{id}.
- Carrier: req.body assigned to local `body` and passed to Object.assign into a new Variable entity, including server-controlled keys like workspaceId.
- Sink: Object.assign(updatedVariable, body) followed by variablesService.updateVariable, which merges and saves the entity to the database.
- Missing guard: No field allowlist / DTO whitelist and no check that body.workspaceId matches the caller's authorized workspace; the user-controlled ownership key is accepted as-is.

## Fix
Commit 7dc48ad (flowise@3.1.2) replaces the blanket Object.assign with an explicit allowlist that copies only name, value and type from the body, and the service layer now reapplies the original workspaceId after merge so the client-supplied workspaceId can never be persisted.

## Scanner Expectation
A scanner should flag the flow from req.body to Object.assign onto a persisted ORM entity (CWE-915 mass assignment) where a user-controlled ownership key (workspaceId, CWE-639) crosses the authorization boundary with no allowlist or ownership re-validation.
