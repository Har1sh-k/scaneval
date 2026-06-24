# SB-TS-RW-107: Expression sandbox escape leading to RCE via spread of Node globals

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-vpcf-gvg4-6qwr`
- CVE: `CVE-2026-27577`
- Vulnerable commit: `8e81f3e31398b04fd6f8cc27cf844980cd382117` (release n8n@2.10.0)
- Fix commit: `562d867483e871b0f1e31776252e23bd721df75b` (release n8n@2.10.1)

## Vulnerability
The expression body is fully attacker-controlled, and the sandbox denylist was incomplete: EMPTY_CONTEXT shadowed only process (leaving require/module/Buffer), and PrototypeSanitizer did not rewrite spread of globals or catch reserved names in destructuring/assignment/loop bindings, so a crafted expression could reach the genuine process global and execute system commands.

## Source / Carrier / Sink
- Source: User-authored n8n workflow expression text (parameter expressions evaluated by the Tournament expression engine).
- Carrier: The parsed expression AST passed through the PrototypeSanitizer after-hook and evaluated with the substituted context.
- Sink: Runtime evaluation of the sanitized expression, which on escape resolves the real Node.js process/global and enables child_process command execution.
- Missing guard: Incomplete sandbox denylist: spread of globals was not blocked and EMPTY_CONTEXT did not shadow require/module/Buffer, allowing recovery of dangerous globals.

## Fix
The fix extends EMPTY_CONTEXT to also shadow require, module and Buffer, adds a getBoundIdentifiers helper so reserved names are detected in destructuring/assignment/update/for-of/for-in positions, and adds visitSpreadElement/visitSpreadProperty hooks that rewrite spreads of process/global/globalThis/Buffer into a safe data-context lookup that throws instead of exposing the real global.

## Scanner Expectation
Flag the expression-sandbox denylist (EMPTY_CONTEXT / PrototypeSanitizer) as an incomplete sanitization guard over attacker-controlled expression input reaching a code-execution sink.
