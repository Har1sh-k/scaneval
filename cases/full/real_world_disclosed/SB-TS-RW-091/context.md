# SB-TS-RW-091: Missing authorization on OpenAI Assistants Vector Store CRUD routes

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-hmg2-jjjx-jcp2`
- CVE: `CVE-2026-46444`
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `b93ccf3109d9d70e121a752411b28a7a36131556` (release flowise@3.1.2)

## Vulnerability
The route definitions wire each controller handler directly with no checkPermission()/checkAnyPermission() middleware, so authorization is never enforced at the route layer for vector-store operations. Once a request passes global authentication, RBAC scope (assistants:create/view/update/delete) is never validated, allowing privilege-disregarding access to a sensitive resource.

## Source / Carrier / Sink
- Source: HTTP requests to /api/v1/openai-assistants-vector-store from any authenticated session or API key
- Carrier: Express route handlers in openai-assistants-vector-store/index.ts that pass requests straight to controller methods
- Sink: Vector-store CRUD controller operations (create/update/delete/upload/delete files)
- Missing guard: Per-route RBAC permission check (checkPermission/checkAnyPermission on assistants:* scopes)

## Fix
The fix commit b93ccf3109d9d70e121a752411b28a7a36131556 imports checkPermission/checkAnyPermission from the enterprise RBAC module and inserts the appropriate permission middleware (assistants:create, assistants:view, assistants:update, assistants:delete) on each route, placing the upload gate before multer so unauthorized file uploads are rejected before parsing.

## Scanner Expectation
Flag privileged Express routes that invoke state-changing controllers with no authorization middleware in the handler chain
