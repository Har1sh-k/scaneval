# SB-TS-RW-104: Second-order n8n expression injection via Form node HTML field

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-75g8-rv7v-32f7`
- CVE: `CVE-2026-27493`
- Vulnerable commit: `8e81f3e31398b04fd6f8cc27cf844980cd382117` (release n8n@2.10.0)
- Fix commit: `9e5212ecbc5d2d4e6f340b636a5e84be6369882e` (release n8n@2.10.1)

## Vulnerability
The loop resolves expressions found in the HTML field and substitutes their evaluated results back into the markup; because n8n auto-evaluates any string beginning with '=' as an expression, attacker-controlled form data that gets interpolated and starts with '=' is re-evaluated as code rather than treated as inert text. User data thus reaches the expression evaluator (eval-equivalent) without being neutralized.

## Source / Carrier / Sink
- Source: Unauthenticated form submission data provided to an earlier Form/Form Trigger node.
- Carrier: The submitted value interpolated into a downstream Form node HTML field, surfaced as a resolvable inside `html`.
- Sink: context.evaluateExpression(resolvable) called on each resolvable extracted from the HTML field, re-evaluating any '='-prefixed value as an n8n expression.
- Missing guard: No guard preventing already-resolved/user-derived field content from being treated and evaluated as a new expression (no flagging of '='-prefixed interpolated data; no separation of static markup from expression evaluation).

## Fix
prepareFormFields() was changed to stop evaluating expressions for the production render path: for html fields it now only sanitizes the static field.html (`field.html = sanitizeHtml(field.html)`) and no longer calls context.evaluateExpression on resolved content, while a separate parseFormFields() path handles configured-field expressions explicitly under controlled conditions, eliminating the second-order double evaluation of attacker-supplied values.

## Scanner Expectation
Flag user-influenced data flowing into an expression/eval evaluation sink (evaluateExpression) without sanitization, enabling code/expression injection.
