# SB-GO-RG-005 — oauth2-proxy email_domain authz bypass via malformed email claims

## Summary

oauth2-proxy can restrict access to users whose authenticated email belongs to a configured set of domains (`email_domain`). In versions prior to v7.15.2, the domain check is implemented as a simple `strings.HasSuffix(email, "@"+domain)` test. This admits malformed email claims that contain multiple `@` characters: `attacker@evil.com@company.com` ends with `@company.com`, so it passes the `company.com` allowlist even though the actual mailbox belongs to `evil.com`.

The bypass requires an identity provider or claim mapper that emits malformed claim values without normalising them — typical in self-hosted OIDC setups, federated identity bridges, and custom claim transformers.

## Why it is a real bug

`validator.go:isEmailValidWithDomains`:

```go
func isEmailValidWithDomains(email string, allowedDomains []string) bool {
    for _, domain := range allowedDomains {
        if strings.HasSuffix(email, "@"+domain) {
            return true
        }
        atoms := strings.Split(email, "@")
        if (strings.HasPrefix(domain, ".") && strings.HasSuffix(atoms[len(atoms)-1], domain)) ||
           (strings.HasPrefix(domain, "*.") && strings.HasSuffix(atoms[len(atoms)-1], domain[1:])) {
            return true
        }
    }
    return false
}
```

The naive suffix check, plus the second branch that operates on `atoms[len(atoms)-1]` (the *last* segment after splitting on `@`), both blindly trust that the email contains exactly one `@`. The fix prepends an explicit `strings.Count(email, "@") != 1` guard.

## What a SAST tool should flag

The annotated region is a domain-allowlist enforcement that takes a string and answers "is this email in an allowed domain?" without first checking that the input is a well-formed single-`@` email. A scanner that recognises identity-claim allowlist checks should flag this region.

## References

- Advisory: <https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-c5c4-8r6x-56w3>
- CVE: CVE-2026-40574
- Fix: oauth2-proxy/oauth2-proxy commit `cc0e0335ea9e`
- Vulnerable snapshot: oauth2-proxy/oauth2-proxy at `848ec8ba82e8` (v7.15.1)
