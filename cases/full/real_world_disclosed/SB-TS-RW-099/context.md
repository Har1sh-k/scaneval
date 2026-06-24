# SB-TS-RW-099: n8n expression sandbox escape via reserved-variable shadowing / with statement leading to RCE

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-6cqr-8cfr-67f8`
- CVE: `CVE-2026-25049`
- Vulnerable commit: `61fd8625d744592727ddc2d3cf635cb2fbaa98b1` (release n8n@1.123.16)
- Fix commit: `30383d86139f3279a698df8d229eadfefe8627f4` (release n8n@1.123.17)

## Vulnerability
The PrototypeSanitizer AST hook lacked visitors for VariableDeclarator, Function parameters, CatchClause and WithStatement, so an attacker could re-bind the sandbox's internal ___n8n_data / __sanitize identifiers or introduce a 'with' scope, neutralizing the member-access sanitization that the sandbox relies on. This allowed reaching dangerous prototype/constructor chains and executing arbitrary JavaScript on the host.

## Source / Carrier / Sink
- Source: Authenticated user input: expressions in workflow node parameters.
- Carrier: Expression string parsed into an AST and transformed by PrototypeSanitizer before evaluation in the expression sandbox.
- Sink: Sandboxed JavaScript evaluation of the transformed expression (code execution on the n8n host).
- Missing guard: No rejection of expressions that redeclare reserved sandbox identifiers (___n8n_data, __sanitize) or use 'with' statements, allowing the sanitizer to be bypassed.

## Fix
The fix adds visitVariableDeclarator, visitFunction and visitCatchClause visitors that throw ExpressionReservedVariableError when an expression tries to declare a reserved name (___n8n_data or __sanitize), and a visitWithStatement visitor that throws ExpressionWithStatementError, closing the sandbox-escape vectors.

## Scanner Expectation
Flag the incomplete AST-based sanitizer that fails to constrain attacker-controlled expression code before sandboxed evaluation, permitting arbitrary code/command execution (CWE-94/RCE).
