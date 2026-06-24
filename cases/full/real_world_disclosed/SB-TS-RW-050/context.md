# SB-TS-RW-050: OpenClaw Active Memory global enable/disable mutated global config without operator.admin scope

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-x629-46cc-7xgw`
- CVE: `CVE-2026-53847`
- Vulnerable commit: `b1abf9d8ae4410c6a6e08f7dfd2d617f4550281c` (release v2026.5.5)
- Fix commit: `5852f5d15cdc5e2c458f2b8d4a7ad67ebeef9db1` (release v2026.5.7)

## Vulnerability
The `if (isGlobal)` branch writes global configuration (replaceConfigFile with the mutated global-enabled config) but never verifies that the caller holds operator.admin; only operator.write to the command was required. This lets a write-scoped operator perform an admin-scoped global config mutation.

## Source / Carrier / Sink
- Source: A Gateway client/caller holding only operator.write scope invoking `/active-memory --global on|off`.
- Carrier: The isGlobal enable/disable branch of the Active Memory command handler builds a mutated global config via updateActiveMemoryGlobalEnabledInConfig.
- Sink: api.runtime.config.replaceConfigFile() persists the change to the Gateway global configuration file.
- Missing guard: No operator.admin scope check before performing the global configuration write; the action is gated only by command write access.

## Fix
The fix adds requiresAdminToMutateActiveMemoryGlobal(ctx.gatewayClientScopes), which returns a refusal message (and does not mutate config) when a gateway client's scopes do not include operator.admin. The guard is invoked immediately after the global `status` read and before the enable/disable replaceConfigFile calls, so global toggles now require operator.admin.

## Scanner Expectation
A scanner should flag the privileged global-config write (replaceConfigFile in the isGlobal branch) that lacks an operator.admin authorization check, as an authorization/scope-escalation flaw.
