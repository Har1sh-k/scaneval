# SB-TS-RG-003 — Next.js middleware pathname authorization bypass

## Summary

Next.js middleware commonly authorises incoming requests by inspecting `req.nextUrl.pathname` (e.g., "redirect anything under `/admin/*` to login"). In versions prior to 14.2.15 (and equivalent backports), the server processes `__nextLocale` and related query parameters at the very start of request handling without checking whether they correspond to a configured i18n locale. The unverified locale value influences the pathname that middleware ultimately observes, while the underlying route still resolves to the protected resource. A request crafted with a `__nextLocale` value shifts the pathname seen by middleware away from the protected prefix, bypassing pathname-based authorization.

The fix introduces `I18NProvider.validateQuery` and, at the request-entry point in `base-server.ts`, strips `__nextLocale`, `__nextDefaultLocale`, and `__nextInferredLocaleFromDefault` from the query when i18n is disabled or the supplied locale is not in the configured list. With the strip in place, middleware sees the canonical pathname.

## Why it is a real bug

In `packages/next/src/server/base-server.ts`, the request-entry section sets X-Forwarded-* headers and immediately calls `attachRequestMeta` without inspecting the query for locale parameters. The fix wedges a validation step into exactly this region:

```ts
// after this line in the fix:
if (!this.i18nProvider?.validateQuery(parsedUrl.query)) {
    delete parsedUrl.query.__nextLocale
    delete parsedUrl.query.__nextDefaultLocale
    delete parsedUrl.query.__nextInferredLocaleFromDefault
}
this.attachRequestMeta(req, parsedUrl)
```

So in the vulnerable snapshot, the annotated region reflects the missing-validation primitive: attacker-controlled query parameters with reserved Next.js names propagate into request metadata used by middleware.

## What a SAST tool should flag

A scanner that recognises "request input used to derive a pathname or routing decision without validation" should flag this region. The taint chain runs from `parsedUrl.query.__nextLocale*` (attacker-controlled) into `attachRequestMeta` and downstream pathname construction.

## References

- Advisory: <https://github.com/vercel/next.js/security/advisories/GHSA-7gfc-8cq8-jh5f>
- CVE: CVE-2024-51479
- Fix: vercel/next.js commit `1c8234eb20bc` (PR #70976, backport of #70761)
- Vulnerable snapshot: vercel/next.js at `bb3f58011885` (parent of fix on the v14.2.x release branch)
