# SB-TS-RW-066: Cross-workspace chatflow disclosure via missing workspace scope in getChatflowByApiKey

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-c2c9-mfw7-p8hw`
- CVE: ``
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `f7d86912fa43b2c77a7cba1b4171a0a236a72bdb` (release flowise@3.1.2)

## Vulnerability
The database query authorizes results solely on apikeyid and an unscoped orWhere(apikeyid IS NULL/empty) branch, with no tenant/workspace boundary applied. Because most chatflows are created without an API key, the OR clause exposes the majority of chatflows in a multi-workspace deployment to any API-key holder, an incorrect-authorization (cross-tenant) flaw.

## Source / Carrier / Sink
- Source: API-key-authenticated request to /api/v1/chatflows/apikey/:apikey (whitelisted endpoint)
- Carrier: apiKeyId argument and the keyonly query flag flowing into the QueryBuilder
- Sink: TypeORM getMany() returning full ChatFlow entities across all workspaces
- Missing guard: Workspace-scope predicate (cf.workspaceId = caller's workspace) on the chatflow query

## Fix
Fix commit f7d86912fa43b2c77a7cba1b4171a0a236a72bdb adds a workspaceId parameter (passed from apikey.workspaceId in the controller) and rewrites the query to require cf.workspaceId = :workspaceId via a TypeORM Brackets group, so the apikey-bound and unbound chatflows are only returned within the caller's own workspace.

## Scanner Expectation
Flag multi-tenant data queries that return resources without filtering by the requester's workspace/tenant identifier
