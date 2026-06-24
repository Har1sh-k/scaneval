# SB-TS-RW-032: OpenClaw internal/webchat command auth inherited wildcard ownerAllowFrom across channels

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-4hpg-mp64-x7xq`
- CVE: `CVE-2026-53854` (CWE-863 Incorrect Authorization)
- Vulnerable commit: `cbcfdf62c7297bda66009ea7476f053c3e9addab` (release v2026.4.24)
- Fix commit: `fef42acda0467c6317b3a1451795f46c133eb2a5` ("fix(commands): scope owner allowlist prefixes", #72928; first shipped in v2026.4.29)

## Scenario

OpenClaw authorizes privileged ("owner") commands using an `ownerAllowFrom` allowlist. Entries can be channel-prefixed (e.g. `discord:<id>`) so that an owner identity on one messaging channel does not automatically authorize commands arriving on another. `resolveOwnerAllowFromList()` in `src/auto-reply/command-auth.ts` is responsible for keeping each entry scoped to its channel.

## Vulnerability

The channel-scoping guard (lines 291-294) is:

```ts
if (channel) {
  if (params.providerId && channel !== params.providerId) {
    continue;
  }
```

A channel-prefixed entry is only skipped when `params.providerId` is set **and** differs from the entry's channel. On internal and webchat command paths `params.providerId` is left unset, so `params.providerId && ...` short-circuits to `false`, the `continue` is skipped, and the entry's owner allowlist remainder is accepted regardless of the channel it was scoped to. Channel-scoped (and wildcard) `ownerAllowFrom` state therefore leaks across channel boundaries, granting owner-style command authorization to senders on internal/webchat paths who should remain channel-scoped.

## Source / Carrier / Sink
- Source: a sender on an internal or webchat command path where `params.providerId` is unset
- Carrier: `resolveOwnerAllowFromList()` fails to drop channel-prefixed entries when the provider is unknown, because the guard requires `params.providerId` to be truthy before it will `continue`
- Sink: the command authorization check treats the sender as an allowlisted owner and runs the privileged command
- Missing guard: the fix inverts the guard to `if (!params.providerId || channel !== params.providerId) continue;`, dropping channel-prefixed entries whenever the provider is unknown or mismatched

## Scanner Expectation
A scanner should flag the authorization guard at lines 291-294 as an authorization bypass: a channel-scoping check that is only enforced when `providerId` is present, so an unset provider (internal/webchat) inherits owner allowlist state across channel boundaries.
