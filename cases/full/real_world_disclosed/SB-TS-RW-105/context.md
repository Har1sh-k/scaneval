# SB-TS-RW-105: JavaScript Task Runner sandbox escape via incomplete global freezing enabling arbitrary host code execution

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-jjpj-p2wh-qf23`
- CVE: `CVE-2026-27495`
- Vulnerable commit: `8e81f3e31398b04fd6f8cc27cf844980cd382117` (release n8n@2.10.0)
- Fix commit: `562d867483e871b0f1e31776252e23bd721df75b` (release n8n@2.10.1)

## Vulnerability
The freeze loop only calls Object.freeze on each global function's prototype, not on the function/constructor object itself, and never freezes the Reflect, JSON and Math namespaces. This leaves attacker-controllable mutation surface (static methods, constructor properties) intact inside the vm sandbox, which can be chained to escape the context and reach the real Node.js runtime.

## Source / Carrier / Sink
- Source: User-authored JavaScript code submitted via a workflow Code node and dispatched to the JS Task Runner.
- Carrier: The vm sandbox execution context whose globals are only partially frozen during runner initialization.
- Sink: Arbitrary code execution on the Task Runner host (Node.js runtime) after escaping the vm sandbox.
- Missing guard: Failure to freeze the global function/constructor objects themselves (only their prototypes were frozen) and failure to freeze Reflect/JSON/Math, leaving mutable escape surface.

## Fix
The fix freezes both the function objects and their prototypes (Object.freeze(fn) plus the prototype) and additionally freezes Reflect, JSON and Math; it also removes the mutable Buffer proxy by hard-overwriting allocUnsafe/allocUnsafeSlow with Buffer.alloc, drops the injected module object, and freezes all core constructors inside the generated vm wrapper to prevent static-method mutation.

## Scanner Expectation
Flag the sandbox-hardening routine that freezes only fn.prototype as an incomplete sandbox boundary permitting code-injection/sandbox escape from untrusted vm-executed code.
