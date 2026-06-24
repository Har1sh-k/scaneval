# SB-TS-RW-037: Zalo sendPhoto forwards outbound photo URL to Zalo Bot API without applying the SSRF hostname policy

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-2hh7-c75g-qj2r`
- CVE: `CVE-2026-44116`
- Vulnerable commit: `f788c88b4c508c335336fb292afed8c900656d6d` (release v2026.4.21)
- Fix commit: `a65eb1b864b7630c1242a82de9e5799b80583c3f` (release v2026.4.22)

## Vulnerability
sendPhoto() (and its caller sendPhotoZalo) never ran the photo URL through resolvePinnedHostnameWithPolicy or any HTTP/HTTPS protocol check, so any host the caller supplied was accepted and forwarded to Zalo. OpenClaw enforces a shared SSRF policy on other outbound media paths, but this Zalo send path bypassed that guard entirely.

## Source / Carrier / Sink
- Source: Attacker-controlled outbound photo URL supplied to the Zalo plugin (params.photo).
- Carrier: sendPhoto() in extensions/zalo/src/api.ts passes the URL unmodified into callZaloApi, which posts it to the Zalo Bot API.
- Sink: The Zalo Bot API performs a server-side fetch of the supplied photo URL, completing the SSRF outbound request.
- Missing guard: No URL parse, no HTTP/HTTPS protocol restriction, and no resolvePinnedHostnameWithPolicy SSRF hostname validation before forwarding the URL.

## Fix
The fix makes sendPhoto parse the photo URL with new URL(), reject non-HTTP(S) protocols, and call resolvePinnedHostnameWithPolicy(parsedPhotoUrl.hostname, { policy: ZALO_MEDIA_SSRF_POLICY }) before posting to the Zalo API. Media-reply paths were additionally rerouted through the guarded outbound media helpers (outbound-media.ts).

## Scanner Expectation
Flag sendPhoto at lines 170-176 as an SSRF sink: a caller-controlled URL reaches an outbound network request (Zalo API photo fetch) with no SSRF hostname/protocol validation applied.
