# SB-TS-RG-004 — React Server Components reply parser RCE

## Summary

React Server Components (RSC) split rendering between server and client. When a client invokes a Server Action, the request body is parsed back into JavaScript values by the *reply parser* (`packages/react-server/src/ReactFlightReplyServer.js`). Among the value types the parser resurrects are *Server References* — pointers to specific server-side function exports identified by an opaque id and resolved through the bundler config (`resolveServerReference(bundlerConfig, id)` → `requireModule(...)`).

In React 19.0.0 / 19.1.0 / 19.1.1 / 19.2.0 the reply parser was missing the cycle-resolution and deferred-error-handling refactors that had already been applied to `ReactFlightClient`. The result is a chain in which an attacker-controlled id from an inbound RSC reply payload is resolved into a module reference and `require()`d by the server, providing unauthenticated RCE in any server that has Server Components enabled (Next.js App Router, frameworks/bundlers that support RSC).

This advisory ships in the React repo (`facebook/react`); Next.js's GHSA points downstream consumers at it. The Next.js fix is a dependency bump to a patched React.

## Why it is a real bug

`loadServerReference` accepts an `id` whose origin is the parsed RSC reply payload — meaning, ultimately, the inbound HTTP body. It hands that id to `resolveServerReference(response._bundlerConfig, id)` and then calls `requireModule(serverReference)` synchronously (line 365) or asynchronously (line 361). The bundler config is a server-side trust boundary that maps ids to module paths; an attacker who can sufficiently influence the id (or who exploits cycles in the surrounding model graph that defeat the prior defences) reaches `requireModule` with a value of their choosing.

```js
function loadServerReference<T>(response, id, bound, parentChunk, parentObject, key): T {
  const serverReference = resolveServerReference(response._bundlerConfig, id);
  const preloadPromise = preloadModule(serverReference);
  // … requireModule(serverReference) called below in either branch …
}
```

## What a SAST tool should flag

This case is the "deserialization of untrusted input into a module loader" pattern in JavaScript. A scanner with a rule for "`require`/dynamic import driven by a request-derived value" or "function reference resolved from network-supplied id" should flag the annotated region.

This is acknowledged to be a hard case for generic SAST — the dataflow runs through several reviver layers and the bug is in part the absence of cycle/error guards that exist on the sibling code path. We include it as a real-world stress case for code-review-style scanners.

## References

- Advisory (React): <https://github.com/facebook/react/security/advisories/GHSA-fv66-9v8q-g76r>
- Advisory (Next.js downstream): <https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp>
- CVE: CVE-2025-55182
- Fix: facebook/react commit `bbed0b0ee64b` ("Bring ReactFlightClient fixes to FlightReplyServer")
- Vulnerable snapshot: facebook/react at `f3e3f6fbac29` (parent of fix)
