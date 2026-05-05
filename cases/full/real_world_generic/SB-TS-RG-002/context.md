# SB-TS-RG-002 — Next.js Server Actions SSRF

## Summary

Next.js Server Actions can issue internal redirects. When the redirect target is app-relative, the server "saves a roundtrip" by fetching the target itself rather than returning a 3xx to the browser. Versions prior to 14.1.1 build that internal fetch URL from the inbound `Host` header without validation — but the `Host` header is attacker-controlled. By sending a request whose `Host` header points at an internal address, an attacker can make the server fetch from that address and stream the response back, achieving SSRF.

## Why it is a real bug

In `packages/next/src/server/app-render/action-handler.ts`, the function that materialises the app-relative redirect:

1. Reads `originalHost.value` (the `Host` header).
2. Constructs `fetchUrl = new URL(`${proto}://${host}${basePath}${parsedRedirectUrl.pathname}`)`.
3. Calls `fetch(fetchUrl, …)`.

Because the host is taken straight from the inbound request, an attacker who can reach the Server Action endpoint can control where this fetch lands. The fix in PR #62561 introduces a `__NEXT_PRIVATE_HOST` environment variable that the server uses by preference, so it no longer trusts the request header for the internal hop.

## What a SAST tool should flag

A scanner that follows tainted-data flow from request headers into outbound network calls (`fetch()`) should flag this region. The taint chain is short and obvious: header value → URL constant → fetch.

## References

- Advisory: <https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g>
- CVE: CVE-2024-34351
- Fix: vercel/next.js commit `8f7a6ca7d21a` (PR #62561)
- Vulnerable snapshot: vercel/next.js at `eb6867fdade2`
