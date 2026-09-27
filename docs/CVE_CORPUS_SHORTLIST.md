# Draft pilot evidence

These public-source notes are referenced by [the pilot pack](../corpus/pilot/pack.json).
They support candidate selection, not human approval of a benchmark label. Advisory version
ranges and fix pointers must be checked against the exact evaluated snapshot and its assumptions.

<a id="03-fastmcp"></a>

## FastMCP: CVE-2026-32871

- Advisory: [CVE-2026-32871 / GHSA-vv7q-7jx5-f767](https://github.com/advisories/GHSA-vv7q-7jx5-f767).
- Recorded publication dates: CVE `2026-04-02`, GHSA `2026-03-31`; verify these against the source records during label review.
- Reported affected range: PyPI `fastmcp < 3.2.0`; first patched version `3.2.0`.
- Public fix: [PR #3507](https://github.com/PrefectHQ/fastmcp/pull/3507) and
  [commit `40bdfb6`](https://github.com/PrefectHQ/fastmcp/commit/40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71).
- Candidate mechanism: client-controlled path parameters reach `RequestDirector._build_url()`
  through unencoded substitution followed by URL joining. The resulting backend request can
  escape the intended API prefix while retaining authorization headers. This concerns outbound
  URL construction, not filesystem traversal; model-generated input is not required.
- Review requirements: establish provider enablement, backend endpoints, authorization headers,
  network assumptions, source locations, and impact in the pinned vulnerable snapshot.

<a id="13-fastify"></a>

## Fastify: CVE-2026-76169

- Advisory: [CVE-2026-76169 / GHSA-p68q-wchp-6fh7](https://github.com/fastify/fastify/security/advisories/GHSA-p68q-wchp-6fh7).
- Recorded CVE publication date: `2026-09-04`; verify it against the CVE record during label review.
- Reported affected range: `fastify >=4.0.0,<5.12.2`; patched version `5.12.2`.
- Public fix: [commit `d66ebd1`](https://github.com/fastify/fastify/commit/d66ebd121c5a621ab0b03569fc75bd1cf829e52a),
  which changes `lib/four-oh-four.js` and focused 404/router tests.
- Candidate mechanism: a malformed request target under one plugin prefix reaches a sibling
  plugin's custom not-found handler and skips its `preHandler`. The relevant deployment returns
  protected information from that fallback and relies on the skipped authentication hook. This
  is not a claim that all Fastify routes bypass authentication.
- Review requirements: confirm custom handlers, prefix layout, authentication placement, the
  pinned source, and accepted reporting locations. The advisory also describes a skipped global
  `onRequest` hook; do not assume that configuration is a mitigation without checking the flow.
