# SB-GO-RG-007 — crewjam/saml multiple-Assertion signature bypass (Grafana CVE-2022-41912)

## Summary

`crewjam/saml` is the SAML implementation that Grafana Enterprise (and many other Go services) uses for SAML SSO. In versions through 0.4.8, the library decides that a SAML response is "signature-validated" whenever one of these is true:

- the `<Response>` element carries a valid signature, or
- the *first* `<Assertion>` element it finds carries a valid signature.

A SAML response can contain multiple `<Assertion>` elements. Downstream code consumes assertions beyond the first, with no per-assertion signature requirement. An attacker who intercepts a legitimate SAML response (with one signed assertion that proves the user is a valid IdP login) can append additional unsigned assertions — including one that asserts Admin role or a different `NameID` — and the response still passes validation.

This is the upstream root cause of Grafana's CVE-2022-41912; the user-visible symptom in Grafana was login as Admin via a tampered SAML response.

## Why it is a real bug

`service_provider.go:validateSigned`:

```go
func (sp *ServiceProvider) validateSigned(responseEl *etree.Element) error {
    haveSignature := false

    sigEl, err := findChild(responseEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
    if sigEl != nil {
        if err = sp.validateSignature(responseEl); err != nil {
            return fmt.Errorf("cannot validate signature on Response: %v", err)
        }
        haveSignature = true
    }

    assertionEl, err := findChild(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
    if assertionEl != nil {
        sigEl, err := findChild(assertionEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
        if sigEl != nil {
            if err = sp.validateSignature(assertionEl); err != nil { ... }
            haveSignature = true
        }
    }

    if !haveSignature {
        return errors.New("either the Response or Assertion must be signed")
    }
    return nil
}
```

`findChild` returns the *first* matching child. Additional sibling `<Assertion>` elements are never inspected here, but downstream code reads them. The fix in v0.4.9 reworks the parser to require that all assertions be signed (or that the response itself is signed) before any are accepted.

## What a SAST tool should flag

A scanner with rules for "signature validation that uses 'first matching element' semantics on a multi-element collection" or "SAML / XMLDSig validation that does not iterate all signed elements" should fire on the annotated region. Even a generic rule that recognises `findChild` (single-result lookup) used in a security boundary applies.

## References

- Upstream advisory (crewjam/saml): <https://github.com/crewjam/saml/security/advisories/GHSA-j2jp-wvqg-wc2g>
- Downstream advisory (Grafana): <https://github.com/grafana/grafana/security/advisories/GHSA-5hcf-rqj9-xh96>
- CVE: CVE-2022-41912
- Fix: crewjam/saml commit `aee3fb1edeea` (PR for GHSA-j2jp-wvqg-wc2g)
- Vulnerable snapshot: crewjam/saml at `5e0ffd290abf` (v0.4.8)
