# SB-TS-RW-096: SSO enforcement bypass via self-service /me/settings endpoint

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-vjf3-2gpj-233v`
- CVE: ``
- Vulnerable commit: `036ef0195a9475d3c1709ccdf127eaae44a99144` (release n8n@2.7.2)
- Fix commit: `a70b2ea379086da3de103bb84811e88cadf29976` (release n8n@2.8.0)

## Vulnerability
The self-service endpoint applies no field-level authorization: it accepts the full admin SettingsUpdateRequestDto (which permits allowSSOManualLogin) and forwards it to updateSettings(id, payload) for the requesting user. A privileged, admin-only setting is therefore writable by any authenticated user on their own record, constituting a privilege escalation / authorization bypass.

## Source / Carrier / Sink
- Source: Authenticated (SSO) user's HTTP request body to PATCH /me/settings.
- Carrier: The payload bound to SettingsUpdateRequestDto, including the admin-only allowSSOManualLogin field.
- Sink: await this.userService.updateSettings(id, payload) persisting the unfiltered payload to the caller's own user settings.
- Missing guard: No restriction limiting the self-service endpoint to non-privileged fields; the admin-only allowSSOManualLogin flag is not excluded from the accepted DTO.

## Fix
The fix introduces a restricted UserSelfSettingsUpdateRequestDto that only permits truly self-serviceable fields (easyAIWorkflowOnboarded, dismissedCallouts) and explicitly excludes allowSSOManualLogin and userActivated; the /me/settings handler now binds to this DTO instead of SettingsUpdateRequestDto, so users can no longer change their own SSO enforcement flag.

## Scanner Expectation
Flag a self-service settings update endpoint that accepts and persists privileged/admin-only fields supplied by the requesting user, enabling authorization bypass / privilege escalation.
