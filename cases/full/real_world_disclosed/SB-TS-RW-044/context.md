# SB-TS-RW-044: Webhook route secret cached per target, leaving rotated SecretRef secret valid until restart

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-q8ff-7ffm-m3r9`
- CVE: `CVE-2026-45005`
- Vulnerable commit: `00bd2cf7a376f1fba26291c6c4766f1f15cbdfa5` (release v2026.4.22)
- Fix commit: `36c4a372a0ad5dca8bfc0d93f7aab9c2f2de66fa` (release v2026.4.23)

## Vulnerability
Caching the resolved SecretRef value for the handler lifetime decouples webhook authentication from the live secret store, so 'secrets reload' does not invalidate the in-memory copy. The stale credential keeps passing the constant-time secret comparison, allowing continued authorized invocation of the configured webhook task flow.

## Source / Carrier / Sink
- Source: An incoming webhook HTTP request presenting a route secret, sent by an attacker who holds a previously valid (now-rotated) route secret.
- Carrier: resolveTargetSecret returning the cached secretByTarget promise instead of re-reading the current SecretRef value.
- Sink: Webhook route authentication comparing the request-supplied secret against the cached resolved secret to authorize the task-flow action.
- Missing guard: No per-request (or post-reload) re-resolution / cache invalidation of SecretRef-backed route secrets, so rotated credentials are not enforced.

## Fix
The fix removes the secretByTarget WeakMap cache and makes resolveTargetSecret async, re-resolving the SecretRef on every request via resolveConfiguredSecretInputString (returning inline string secrets directly). A rotated secret takes effect after 'openclaw secrets reload' without a restart, and the old secret is rejected.

## Scanner Expectation
Flag that an authentication credential is cached without expiration/invalidation on rotation, so the comparison authorizes requests using a stale secret (insufficient credential/session expiration).
