# SB-JV-RG-001 — OpenAM FreeMarker template injection (RCE)

## Summary

OpenAM lets each realm configure a "custom login URL template" that the OAuth2 provider renders to build the URL the user is redirected to for authentication. In versions 15.0.3 and earlier, that template is compiled with a default FreeMarker `Configuration` whose built-in class resolver is permissive. FreeMarker's `?new()` directive can then instantiate arbitrary Java classes — most notably `freemarker.template.utility.Execute`, which runs OS commands. An attacker who can influence the template string achieves pre-authenticated remote code execution by visiting an OAuth2 endpoint that triggers template rendering.

## Why it is a real bug

In `openam-oauth2/.../RealmOAuth2ProviderSettings.java`, `getCustomLoginUrlTemplate()`:

```java
String loginUrlTemplateString = settings.getStringSetting(...);
if (loginUrlTemplateString != null) {
    loginUrlTemplate = new Template("customLoginUrlTemplate",
        new StringReader(loginUrlTemplateString), new Configuration());
}
```

The `Configuration` is freshly constructed with defaults and never restricts `setNewBuiltinClassResolver`, so the resulting `Template` is willing to instantiate any class via `?new()`. The fix sets `loginUrlTemplate.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`.

Public PoC payload from the advisory:

```
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc")}
```

## What a SAST tool should flag

Java SAST rules for FreeMarker template injection typically flag a `new Template(...)` constructed from a user-influenced string when the configuration does not restrict the new-builtin class resolver. The annotated region covers the unsafe `Template`/`Configuration` construction.

## References

- Advisory: <https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-7726-43hg-m23v>
- CVE: CVE-2024-41667
- Fix: OpenIdentityPlatform/OpenAM commit `fcb8432aa77d`
- Vulnerable snapshot: OpenIdentityPlatform/OpenAM at `ba0c9382d04b`
