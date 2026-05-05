# SB-TS-RG-001 — Next.js middleware authorization bypass

## Summary

Next.js middleware runs on the Edge runtime and is commonly used for request-level authentication and authorization. In versions prior to 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5, the Edge sandbox tracks middleware recursion using an HTTP header (`x-middleware-subrequest`) that the runtime trusts unconditionally. An external attacker can supply the header on an inbound request and trick the runtime into believing it has already recursed into middleware too many times. The runtime then short-circuits and returns a response that tells the upstream code to continue without middleware — bypassing every check the middleware enforces, including authorization gates.

## Why it is a real bug

In `packages/next/src/server/web/sandbox/sandbox.ts`, `run()` reads the `x-middleware-subrequest` header off the inbound request, splits it on `:`, counts how many times the current middleware's name appears, and skips middleware execution entirely if the count reaches `MAX_RECURSION_DEPTH` (5). Because the header is attacker-controlled, sending `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` is sufficient to satisfy the check and bypass the middleware on every request.

The fix introduces a session-scoped `x-middleware-subrequest-id` token: only requests that carry the matching token (set internally) are honoured, and inbound copies of `x-middleware-subrequest` are filtered out before reaching the sandbox.

## What a SAST tool should flag

The vulnerable region in `sandbox.ts` reads a header value from an attacker-controlled `params.request.headers` map and uses the parsed result to drive an authorization-relevant control-flow decision (whether to skip middleware). A scanner that tracks tainted-data flow into authorization decisions should flag this as an authorization-bypass risk.

## References

- Advisory: <https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw>
- CVE: CVE-2025-29927
- Fix: vercel/next.js commit `52a078da3884` (PR #77201)
- Vulnerable snapshot: vercel/next.js at `f4552826e1ed` (release tag v15.2.2)
