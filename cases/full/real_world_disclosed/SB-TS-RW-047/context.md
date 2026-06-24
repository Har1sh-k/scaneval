# SB-TS-RW-047: OpenClaw gateway per-RPC dispatch lacked a device-token invalidation re-check, letting revoked node tokens keep authority

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-q99w-vh6v-q3v7`
- CVE: `CVE-2026-53843`
- Vulnerable commit: `a374c3a5bfd5225ce319bce3865aab6216309c4f` (release v2026.5.22)
- Fix commit: `1e1cf14da242280502b28142a8f696675c4c00f6` (release v2026.5.26)

## Vulnerability
Revocation/rotation marks the token invalid but disconnects asynchronously (queueMicrotask), and the per-RPC dispatch has no synchronous invalidation gate for device-token clients (only shared-auth gets a per-request freshness check), so buffered/pipelined frames are dispatched with stale-but-still-accepted device credentials.

## Source / Carrier / Sink
- Source: RPC frames pipelined in the WS socket buffer of an already-paired device whose node token has been revoked/rotated
- Carrier: GatewayWsClient device-token session reused across the queueMicrotask disconnect window in the per-RPC dispatch loop
- Sink: handleGatewayRequest() dispatch executing node-authority operations for the device-token client
- Missing guard: No synchronous per-RPC device-token invalidation re-check before dispatch (shared-auth had a freshness re-check; device-token did not)

## Fix
The fix marks affected clients invalidated synchronously before responding in the three device-credential-mutating handlers (via context.invalidateClientsForDevice), adds a closeInvalidatedClient(client, method) gate plus a deviceCredentialMutationBarrier at the start of per-RPC dispatch in message-handler.ts that force-closes invalidated clients regardless of whether socket.close() has taken effect, and serializes credential-invalidating RPCs.

## Scanner Expectation
Flag that the per-request dispatch path re-validates only shared-gateway-auth freshness and dispatches device-token client RPCs without checking whether the device token/session was invalidated/revoked, permitting use of revoked node authority.
