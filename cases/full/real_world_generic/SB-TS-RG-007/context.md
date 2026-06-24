# SB-TS-RG-007: Next.js Server Actions CSRF bypass: Origin: null treated as missing instead of cross-origin

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-mq59-m269-xvcx`
- CVE: `CVE-2026-27978`
- Vulnerable commit: `adf8c612adddd103647c90ff0f511ea35c57076e` (release v16.1.6)
- Fix commit: `a27a11d78e748a8c7ccfd14b7759ad2b9bf097d8` (release v16.1.7)

## Vulnerability
The literal Origin 'null' is a real, attacker-reachable origin value emitted by sandboxed iframes and other opaque contexts, yet the code explicitly excludes it (`originHeader !== 'null'`) so it collapses to undefined and is treated the same as a missing Origin header. The 'missing origin' path is a deliberate allow-with-warning case for old/handcrafted clients, but those cannot carry the victim's cookies whereas a sandboxed browser context can, so the null origin slips past host/allowlist comparison and the action runs.

## Source / Carrier / Sink
- Source: Attacker-influenced Origin request header with the literal value 'null', sent when a victim browser submits a Server Action from a sandboxed iframe or other opaque/privacy-sensitive context.
- Carrier: originHeader (req.headers['origin']) is mapped to originDomain via `typeof originHeader === 'string' && originHeader !== 'null' ? new URL(originHeader).host : undefined`, turning the 'null' origin into undefined.
- Sink: The CSRF decision branch `if (!originDomain) { warning = 'Missing origin...' }` which lets the Server Action proceed instead of aborting.
- Missing guard: No validation of the literal 'null' origin against the host or experimental.serverActions.allowedOrigins; 'null' is excluded from comparison and silently treated as a missing (allowed) origin.

## Fix
The fix (commit a27a11d, shipped in v16.1.7) replaces originDomain with originHost computed so that an Origin of 'null' is kept as the explicit value 'null' rather than undefined, then runs the same host/origin equality and isCsrfOriginAllowed allowlist checks against it. A null origin is now only accepted if 'null' is explicitly present in experimental.serverActions.allowedOrigins; otherwise it is treated as a cross-origin request and the action is aborted.

## Scanner Expectation
A scanner should flag that the Origin header value 'null' bypasses the Server Action CSRF host/allowlist comparison and reaches the allow-with-warning branch, allowing a cross-origin state-changing request to execute (CSRF / origin-validation bypass, CWE-352).
