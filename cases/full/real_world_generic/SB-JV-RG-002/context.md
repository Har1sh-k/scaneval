# SB-JV-RG-002 — OpenAM jato.clientSession deserialization RCE

## Summary

The JATO framework embedded in OpenAM uses serialized Java objects for two related session-tracking parameters: `jato.pageSession` and `jato.clientSession`. After CVE-2021-35464, OpenAM hardened `jato.pageSession` with a `WhitelistObjectInputStream` that restricts deserialization to a small list of safe classes. The second entry point — `jato.clientSession`, processed by `ClientSession.deserializeAttributes()` — was overlooked. It calls into `Encoder.deserialize()`, which performs an unfiltered `ObjectInputStream.readObject()` on attacker-supplied bytes. JATO ViewBean endpoints whose JSP contains `<jato:form>` tags (e.g., Password Reset, accessible without authentication) reach this code path on every request, giving an unauthenticated attacker pre-auth RCE.

## Why it is a real bug

In `jato-shaded/.../Encoder.java`, `deserialize` reads bytes from a parameter under attacker control and round-trips them through `ApplicationObjectInputStream.readObject()`. Although the surrounding stream class is named "Application…", it does not constrain which classes may be deserialized. Any gadget chain available on the classpath becomes exploitable.

```java
public static Object deserialize(byte[] b, boolean compressed) throws IOException, ClassNotFoundException {
    ByteArrayInputStream bais = new ByteArrayInputStream(b);
    InflaterInputStream iis = null;
    ObjectInputStream ois = null;
    if (compressed) {
        iis = new InflaterInputStream(bais);
        ois = new ApplicationObjectInputStream(iis);
    } else {
        ois = new ApplicationObjectInputStream(bais);
    }
    Object result = ois.readObject();   // ← unrestricted gadget chain
    return result;
}
```

The fix delegates to `IOUtils.deserialise`, which uses the same whitelisted ObjectInputStream that already guards `jato.pageSession`.

## What a SAST tool should flag

This is a textbook insecure-deserialization sink. Any rule for `ObjectInputStream.readObject()` reached from a request-derived byte source should flag the annotated region. Signatures that look for `new ObjectInputStream` without a class filter, or that taint-trace HTTP parameters into `readObject`, will land here.

## References

- Advisory: <https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-2cqq-rpvq-g5qj>
- CVE: CVE-2026-33439
- Fix: OpenIdentityPlatform/OpenAM commit `014007c63cac`
- Vulnerable snapshot: OpenIdentityPlatform/OpenAM at `ab64dedfa722`
