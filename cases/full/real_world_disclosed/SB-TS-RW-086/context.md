# SB-TS-RW-086: Flowise tool update endpoint mass-assigns request body, allowing cross-workspace reassignment of tools

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-x5v6-pj28-cwwm`
- CVE: `CVE-2026-42862`
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `f8defac0d64c8a03928781235ddafa0d889a832a` (release flowise@3.1.2)

## Vulnerability
The service blindly Object.assigns the client-supplied body onto a database entity with no DTO allowlist, so the user controls the workspaceId ownership key that determines authorization scope. Because nothing re-validates the supplied workspaceId against the caller's workspace, the tool can be moved to any workspace, bypassing the tenant-isolation authorization boundary.

## Source / Carrier / Sink
- Source: Authenticated user's HTTP JSON request body (req.body) sent to PUT /api/v1/tools/{id}, forwarded to the service as toolBody.
- Carrier: req.body forwarded unmodified by the controller as toolBody and passed to Object.assign into a new Tool entity, including server-controlled keys like workspaceId.
- Sink: Object.assign(updateTool, toolBody) then repository.merge(tool, updateTool) and repository.save(tool), persisting the entity.
- Missing guard: No field allowlist for toolBody and no check that toolBody.workspaceId matches the caller's authorized workspace; the user-controlled ownership key is accepted as-is.

## Fix
Commit f8defac (flowise@3.1.2) makes the controller build an explicit toolBody allowlist (name, description, color, iconSrc, schema, func) before calling the service, and the service now forces tool.workspaceId = workspaceId (the trusted param) as defense-in-depth so the client-supplied workspaceId is never saved.

## Scanner Expectation
A scanner should flag the flow from req.body forwarded as toolBody to Object.assign onto a persisted ORM entity (CWE-915 mass assignment) where a user-controlled ownership key (workspaceId, CWE-639) crosses the authorization boundary with no allowlist or ownership re-validation.
