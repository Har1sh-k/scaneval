# SB-JV-RG-004 — OpenAM OIDC claims extension trusts attacker-requested claim values

## Summary

When `claims_parameter_supported` is enabled, OIDC clients can ask the provider to return specific values for individual claims via the `claims` request parameter (e.g., `{"id_token":{"email":{"value":"someone@example.com"}}}`). OpenAM dispatches each claim through a Groovy script (`oidc-claims-extension.groovy`). In versions through 15.0.4, the `attributeRetriever` closure that materialises a claim's value returns the *requested* value directly when exactly one value was asked for, without checking that the user actually has that value for the underlying attribute. The issued `id_token` and `userinfo` therefore reflect whatever the caller asked for, not the truth from the directory.

Relying parties that trust the email (or other identity) claim for identification can be made to log in attackers as arbitrary users.

## Why it is a real bug

```groovy
attributeRetriever = { attribute, claim, identity, requested ->
    if (requested == null || requested.isEmpty()) {
        fromSet(claim, identity.getAttribute(attribute))
    } else if (requested.size() == 1) {
        requested.iterator().next()                       // ← attacker-supplied
    } else {
        throw new RuntimeException("...")
    }
}
```

The fix retrieves the real attribute value from `identity.getAttribute(attribute)` and only returns it when `requested.contains(attr)` — i.e., the claim is honoured only if the user already has that value.

## What a SAST tool should flag

A scanner that recognises "value used in an authentication / authorization assertion is taken from request input without verification against the authenticated principal" should flag this region. The attacker-controlled `requested` collection is returned as the claim value with no check against `identity.getAttribute(attribute)`.

## References

- Advisory: <https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-39hr-239p-fhqc>
- CVE: CVE-2025-64099
- Fix: OpenIdentityPlatform/OpenAM commit `4254b34b2b8b`
- Vulnerable snapshot: OpenIdentityPlatform/OpenAM at `ccf03755f063`
