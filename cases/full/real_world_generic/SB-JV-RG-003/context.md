# SB-JV-RG-003 — OpenAM SAMLv1.x signature verification bypass

## Summary

OpenAM's SAMLv1.x Single Sign-On flow (`SAMLPOSTProfileServlet`) accepts a SAML response from the inbound HTTP request and uses it to authenticate a user. In versions through 14.7.2, two related routines in `SAMLUtils.java` fail to enforce that the response is *signed* before deciding it is valid:

- `verifyResponse` calls `response.isSignatureValid()` but never asks whether a signature was present at all. When the response is unsigned, `isSignatureValid()` returns `true` vacuously and the method approves the response.
- `processResponse` only calls `verifySignature` inside an `if (samlResponse.isSigned())` block, so unsigned responses skip signature verification entirely.

Either path lets an unauthenticated attacker submit a forged unsigned SAML response and impersonate any OpenAM user, administrator included.

## Why it is a real bug

The two annotated regions reflect the same root cause: signature checking that is conditional on the attacker having included a signature in the first place. The fix in PR #624 makes verification mandatory: `verifyResponse` returns `false` when the response is unsigned, and `processResponse` runs `verifySignature` unconditionally.

```java
public static boolean verifyResponse(Response response, ...) {
    if (!response.isSignatureValid()) {           // R1
        debug.message("...invalid.");
        return false;
    }
    // …
}

public static Map processResponse(Response samlResponse, String target) {
    if (samlResponse.isSigned()) {                // R2
        boolean isSignedandValid = verifySignature(samlResponse);
        if (!isSignedandValid) {
            throw new SAMLException(bundle.getString("invalidResponse"));
        }
    }
    // …
}
```

## What a SAST tool should flag

Any rule that recognises "signature/MAC verification gated on attacker-supplied condition" or "signature check that doesn't fail-closed on missing signature" should fire on R1 and R2. The annotated regions are a tightly localized signature-validation bug.

## References

- Advisory: <https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-4mh8-9wq6-rjxg>
- CVE: CVE-2023-37471
- Fix: OpenIdentityPlatform/OpenAM commit `7c18543d126e` (PR #624)
- Vulnerable snapshot: OpenIdentityPlatform/OpenAM at `46bce7d6a8ca`
