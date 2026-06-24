# SB-TS-RW-114: IDOR in n8n public API variables endpoint allows cross-project secret disclosure

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-756q-gq9h-fp22`
- CVE: `CVE-2026-42227`
- Vulnerable commit: `732f2a3d3ddba59fb6e51bf2534fd33792a2cde3` (release ?)
- Fix commit: `2d9a2ec76e180b54e8091e31b1e0638c909abd99` (release ?)

## Vulnerability
The handler trusts the attacker-controlled projectId and queries the repository directly (VariablesRepository.findAndCount) instead of going through VariablesService.getAllForUser, so no project-membership/scope check (getProjectIdsWithScope) is applied. Any project's variables can thus be read by supplying that project's id, regardless of the caller's memberships.

## Source / Carrier / Sink
- Source: Authenticated public-API request with API key scope variable:list supplying an arbitrary projectId query parameter.
- Carrier: The projectId value placed into the repository where clause (where: { project: { id: projectId } }).
- Sink: VariablesRepository.findAndCount returning the matching project's variables in the API response.
- Missing guard: No project-membership/authorization check (the user-scoped VariablesService.getAllForUser path) before querying variables by projectId.

## Fix
The fix replaces the direct repository query with Container.get(VariablesService).getAllForUser(req.user, { state, projectId }), which resolves the user's project ids via getProjectIdsWithScope and filters variables to projects the user can access, so a supplied projectId can no longer expose other projects' variables.

## Scanner Expectation
Flag the public-API variables list handler that queries VariablesRepository directly with a client-supplied projectId and no membership check, instead of the user-scoped service (authorization/IDOR bypass).
