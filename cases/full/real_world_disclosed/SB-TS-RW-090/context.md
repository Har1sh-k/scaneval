# SB-TS-RW-090: Authenticated RCE via POST /api/v1/node-custom-function (arbitrary JS execution, NodeVM sandbox escape)

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-9rvc-vf7m-pgm2`
- CVE: `CVE-2026-46442`
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `e765367fdc9761a7d9cf01a048cac15c78903b85` (release flowise@3.1.2)

## Vulnerability
The endpoint forwards attacker-controlled JavaScript straight to a code-execution path with no route-level authorization and, by default, no real isolation: executeJavaScriptCode only uses the external E2B sandbox when E2B_APIKEY is set and otherwise downgrades to NodeVM, which does not contain a host-realm error-constructor escape. The combination of missing authz on a code-execution endpoint and an escapable fallback sandbox yields arbitrary host command execution.

## Source / Carrier / Sink
- Source: body.javascriptFunction in POST /api/v1/node-custom-function from any authenticated session or API key
- Carrier: nodesRouter.executeCustomFunction -> executeCustomNodeFunction -> CustomFunction.init -> executeJavaScriptCode(javascriptFunction, sandbox)
- Sink: Host code execution via NodeVM vm.run fallback reaching process / child_process.execSync
- Missing guard: Route-level RBAC permission check and a fail-closed sandbox policy (no NodeVM downgrade for untrusted code)

## Fix
Fix commit e765367fdc9761a7d9cf01a048cac15c78903b85 gates the route with checkAnyPermission('chatflows:create,chatflows:update,agentflows:create,agentflows:update') and changes executeJavaScriptCode in packages/components/src/utils.ts to fail closed (throw) when useSandbox is requested but E2B_APIKEY is absent, instead of silently falling back to NodeVM for untrusted code.

## Scanner Expectation
Flag an unauthorized Express route that hands user-supplied input into a JavaScript/code-execution sink, enabling arbitrary command execution
