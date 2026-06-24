# SB-TS-RW-109: Credential permission-checker bypass: generic HTTP credential types skipped during pre-execution validation

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-m63j-689w-3j35`
- CVE: `CVE-2026-33663`
- Vulnerable commit: `2374f40ec36795904b4011fb81018da818a76ee8` (release n8n@2.14.0)
- Fix commit: `661e03eab744bc45f7c609c1f5c4907a6ab4af2b` (release n8n@2.14.1)

## Vulnerability
getActiveCredentialTypes() determines which credential types are validated but only accounts for node-type-declared credentials and the nodeCredentialType parameter, not the genericAuthType parameter used by HTTP Request and similar nodes in generic-credential mode. Because the resulting active-type set never contains httpBasicAuth/httpHeaderAuth/httpQueryAuth, mapCredIdsToNodes() skips those credentials entirely (`!activeCredTypes.has(credType) continue`), so the pre-execution permission/ownership check is never applied to them and an unauthorized user's credential ID passes through.

## Source / Carrier / Sink
- Source: An authenticated global:member user supplies a workflow whose HTTP Request node uses authentication=genericCredentialType with a genericAuthType (e.g. httpBasicAuth) referencing another user's generic HTTP credential ID.
- Carrier: The node.credentials map entry for the generic HTTP credential type, whose membership in the active-types set is governed by getActiveCredentialTypes(node).
- Sink: mapCredIdsToNodes() at the skip check `if (activeCredTypes !== null && !activeCredTypes.has(credType)) continue;`, which excludes the generic credential from the set of credentials the pre-execution permission check validates, allowing it to be decrypted and used at runtime.
- Missing guard: getActiveCredentialTypes() fails to add the genericAuthType parameter value to the active credential type set, so generic HTTP credential types are never considered "active" and the ownership/scope authorization check is bypassed for them.

## Fix
The fix adds genericAuthType to the active credential type set: after handling nodeCredentialType, it reads `const { genericAuthType } = node.parameters` and, when it is a non-empty string, calls `activeTypes.add(genericAuthType)`. This ensures generic HTTP credential types are included in the active set so they are no longer skipped and are subjected to the ownership/scope permission check (a companion change adds findByNameAndTypeInProject to scope name-based resolution to the user's project).

## Scanner Expectation
Flag that the per-node active-credential-type computation feeding the pre-execution authorization check omits the user-controlled genericAuthType selector, causing attacker-referenced generic credential types (user-controlled credential key) to be skipped by the permission check (CWE-639 authorization bypass through user-controlled key).
